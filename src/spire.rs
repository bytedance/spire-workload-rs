use super::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use super::workload::*;
use super::{CrlEntry, Identity, CERTIFICATE_REVOKATION_LIST, IDENTITIES, JWT_BUNDLES};
use crate::der::*;
use crate::{JwtBundle, SpiffeID};
use anyhow::*;
use futures::future::Either;
use futures::{Stream, StreamExt};
use log::*;
use rustls::Certificate;
use std::sync::Arc;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::UnixStream;
use tonic::codec::Streaming;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

type ApiClient = SpiffeWorkloadApiClient<Channel>;

async fn prepare_spire_client(unix_file: String) -> Result<ApiClient> {
    let client = Channel::builder(format!("http://127.0.0.1{}", unix_file).parse()?)
        .connect_with_connector(service_fn(|url: Uri| {
            UnixStream::connect(url.path().to_string())
        }))
        .await?;

    Ok(SpiffeWorkloadApiClient::new(client))
}

async fn prepare_spire_svid_stream(client: &mut ApiClient) -> Result<Streaming<X509svidResponse>> {
    let mut request = tonic::Request::new(X509svidRequest {});
    request.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::AsciiMetadataValue::from_str("true")?,
    );
    Ok(client.fetch_x509svid(request).await?.into_inner())
}

async fn prepare_spire_jwt_bundle_stream(
    client: &mut ApiClient,
) -> Result<Streaming<JwtBundlesResponse>> {
    let mut request = tonic::Request::new(JwtBundlesRequest {});
    request.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::AsciiMetadataValue::from_str("true")?,
    );
    Ok(client.fetch_jwt_bundles(request).await?.into_inner())
}

struct MergedStreams<T> {
    inner: Vec<Pin<Box<dyn Stream<Item = T> + Send + Sync>>>,
}

impl<T> Stream for MergedStreams<T> {
    type Item = (Option<T>, usize);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        for (i, item) in self.inner.iter_mut().enumerate() {
            if let Poll::Ready(x) = item.as_mut().poll_next(cx) {
                return Poll::Ready(Some((x, i)));
            }
        }
        if self.inner.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

impl<T> MergedStreams<T> {
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn add_stream<S: Stream<Item = T> + Send + Sync + 'static>(&mut self, stream: S) {
        self.inner.push(Box::pin(stream));
    }
}

#[derive(serde::Deserialize)]
struct JwtBundleContainer {
    keys: JwtBundle,
}

async fn run_spire() -> Result<()> {
    let unix_file = std::env::var("SPIRE_WORKLOAD_URL")
        .unwrap_or_else(|_| "/opt/spire/agent/sockets/agent.sock".to_string());
    let unix_files = unix_file
        .split(':')
        .map(|x| x.to_string())
        .collect::<Vec<_>>();

    let mut clients = vec![]; // exists to keep connections open
    let mut x509_responses = MergedStreams::new();
    let mut jwt_responses = MergedStreams::new();
    info!(
        "Listening on {} sockets: {}",
        unix_files.len(),
        unix_files.join(", ")
    );

    for unix_file in unix_files.iter() {
        let mut client = prepare_spire_client((*unix_file).to_string()).await?;

        let response = prepare_spire_svid_stream(&mut client).await?;
        x509_responses.add_stream(response);
        let response = prepare_spire_jwt_bundle_stream(&mut client).await?;
        jwt_responses.add_stream(response);

        clients.push(client);
    }

    let client_len = clients.len();

    let unix_files_inner = unix_files.clone();
    let handle_x509: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut global_identities: Vec<HashMap<SpiffeID, Arc<Identity>>> =
            (0..client_len).map(|_| HashMap::new()).collect();
        let mut global_crls: Vec<Vec<CrlEntry>> = (0..client_len).map(|_| Vec::new()).collect();

        while let Some((Some(response), i)) = x509_responses.next().await {
            info!("reloading certificates from: {}", unix_files_inner[i]);
            let response = response?;
            let identities = response
                .svids
                .into_iter()
                .map(svid_to_identity)
                .collect::<Result<HashMap<SpiffeID, Arc<Identity>>>>()?;
            global_identities[i] = identities;
            IDENTITIES.store(Arc::new(
                global_identities.iter().cloned().flatten().collect(),
            ));
            let crl = response
                .crl
                .into_iter()
                .map(|x| parse_der_cert_chain(&x[..]))
                .collect::<Result<Vec<Vec<Certificate>>>>()?;
            global_crls[i] = crl.into_iter().flatten().map(CrlEntry).collect();
            CERTIFICATE_REVOKATION_LIST
                .store(Arc::new(global_crls.iter().cloned().flatten().collect()));
            let new_version = super::CURRENT_IDENTITY_VERSION
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            super::IDENTITY_UPDATE_WATCHER.0.send(new_version).ok();
        }
        Ok(())
    });

    let handle_jwt: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut global_jwt_bundles: Vec<HashMap<String, Arc<JwtBundle>>> =
            (0..client_len).map(|_| HashMap::new()).collect();

        while let Some((Some(response), i)) = jwt_responses.next().await {
            info!("reloading jwt bundles from: {}", unix_files[i]);
            let response = response?;
            let bundles = response
                .bundles
                .into_iter()
                .map(|(trust_domain, bundle)| {
                    let bundle: JwtBundleContainer = serde_json::from_slice(&bundle[..])?;
                    Ok((trust_domain, Arc::new(bundle.keys)))
                })
                .collect::<Result<HashMap<String, Arc<JwtBundle>>>>()?;
            global_jwt_bundles[i] = bundles;
            JWT_BUNDLES.store(Arc::new(
                global_jwt_bundles.iter().cloned().flatten().collect(),
            ));
            let new_version = super::CURRENT_IDENTITY_VERSION
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            super::IDENTITY_UPDATE_WATCHER.0.send(new_version).ok();
        }
        Ok(())
    });

    let output = futures::future::select(handle_x509, handle_jwt).await;
    match output {
        Either::Left(x) | Either::Right(x) => x.0.unwrap_or_else(|x| Err(x.into())),
    }
}

pub(super) async fn spire_manager() {
    loop {
        match run_spire().await {
            Ok(()) => {
                warn!("run_spire unexpectedly terminated gracefully, restarting.");
            }
            Err(e) => {
                error!("run_spire terminated for reason: {:?}, restarting.", e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    }
}
