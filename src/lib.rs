#![allow(clippy::len_zero)]

#[macro_use]
extern crate lazy_static;

extern crate anyhow;

pub mod authenticator;
mod der;
mod jwt;
mod pki;
pub mod spiffe;
mod spire;
mod verifier;
mod workload;

pub use authenticator::SpiffeIdAuthorizer;
pub use jwt::{JwtBundle, JwtKey};
pub use spiffe::{SpiffeID, SpiffeIDMatcher};

use crate::der::parse_der_cert_chain;
use anyhow::*;
use arc_swap::ArcSwap;
use rustls::{sign::CertifiedKey, PrivateKey};
use rustls::{Certificate, RootCertStore};
use rustls::{ClientConfig, ServerConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::watch::{channel, Receiver, Sender};
use verifier::DynamicLoadedCertResolverVerifier;

pub struct Identity {
    pub cert_key: Arc<CertifiedKey>,
    pub raw_key: Vec<u8>,
    pub raw_bundle: Vec<Vec<u8>>,
    pub bundle: Arc<RootCertStore>,
}

impl Identity {
    pub fn from_raw(bundle: &[u8], certs: &[u8], key: &[u8]) -> Result<Identity> {
        let certs = parse_der_cert_chain(certs)?;
        let key = rustls::PrivateKey(key.to_vec());
        let bundle = parse_der_cert_chain(bundle)?;
        Self::from_rustls(bundle, certs, key)
    }

    pub fn from_rustls(
        bundle: Vec<Certificate>,
        certs: Vec<Certificate>,
        key: PrivateKey,
    ) -> Result<Identity> {
        let cert_key = CertifiedKey::new(
            certs,
            rustls::sign::any_supported_type(&key)
                .map_err(|_| anyhow!("unsupported private key type"))?,
        );
        let mut root_store = RootCertStore { roots: vec![] };
        for bundle_cert in bundle.iter() {
            root_store.add(bundle_cert)?;
        }
        Ok(Identity {
            cert_key: Arc::new(cert_key),
            raw_key: key.0,
            raw_bundle: bundle.into_iter().map(|x| x.0).collect(),
            bundle: Arc::new(root_store),
        })
    }
}

#[derive(Eq, Clone)]
pub struct CrlEntry(pub Certificate);

impl std::hash::Hash for CrlEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

impl PartialEq for CrlEntry {
    fn eq(&self, other: &CrlEntry) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for CrlEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0 .0.partial_cmp(&other.0 .0)
    }
}

impl Ord for CrlEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0 .0.cmp(&other.0 .0)
    }
}

pub static CURRENT_IDENTITY_VERSION: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    pub(crate) static ref IDENTITY_UPDATE_WATCHER: (Sender<u64>, Receiver<u64>) = channel(0);
    pub static ref IDENTITIES: ArcSwap<BTreeMap<SpiffeID, Arc<Identity>>> = ArcSwap::new(Arc::new(BTreeMap::new()));
    pub static ref JWT_BUNDLES: ArcSwap<BTreeMap<String, Arc<JwtBundle>>> = ArcSwap::new(Arc::new(BTreeMap::new()));
    // unused
    pub static ref CERTIFICATE_REVOKATION_LIST: ArcSwap<BTreeSet<CrlEntry>> = ArcSwap::new(Arc::new(BTreeSet::new()));
}

pub async fn wait_for_identity_update(current_version: Option<u64>) -> Option<u64> {
    let current_version =
        current_version.unwrap_or_else(|| CURRENT_IDENTITY_VERSION.load(Ordering::SeqCst));
    let mut receiver = IDENTITY_UPDATE_WATCHER.1.clone();
    loop {
        receiver.changed().await.ok()?;
        let latest_version = *receiver.borrow();
        if latest_version <= current_version {
            continue;
        }
        return Some(latest_version);
    }
}

pub fn init() {
    tokio::spawn(spire::spire_manager());
}

pub fn init_mock(identities: BTreeMap<SpiffeID, Arc<Identity>>, crl: Vec<Certificate>) {
    IDENTITIES.store(Arc::new(identities));
    CERTIFICATE_REVOKATION_LIST.store(Arc::new(crl.into_iter().map(CrlEntry).collect()));
}

pub fn make_client_config(
    identity: Option<SpiffeID>,
    protocols: &[Vec<u8>],
    authorizer: Box<dyn SpiffeIdAuthorizer>,
    require_server_auth: bool,
) -> rustls::ClientConfig {
    let dyn_resolver_verifier = Arc::new(DynamicLoadedCertResolverVerifier {
        identity,
        authorizer,
        require_client_auth: require_server_auth,
    });

    let mut config = ClientConfig::builder()
        .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .expect("create client config fail")
        .with_custom_certificate_verifier(dyn_resolver_verifier.clone())
        .with_no_client_auth();

    config.alpn_protocols = Vec::from(protocols.clone());
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.client_auth_cert_resolver = dyn_resolver_verifier.clone();

    config
}

pub fn make_server_config(
    identity: Option<SpiffeID>,
    protocols: &[Vec<u8>],
    authorizer: Box<dyn SpiffeIdAuthorizer>,
    require_client_auth: bool,
) -> rustls::ServerConfig {
    let dyn_resolver_verifier = Arc::new(DynamicLoadedCertResolverVerifier {
        identity,
        authorizer,
        require_client_auth,
    });

    let mut config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .expect("create server config failed")
        .with_client_cert_verifier(dyn_resolver_verifier.clone())
        .with_cert_resolver(dyn_resolver_verifier.clone());

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    config.cert_resolver = dyn_resolver_verifier;

    config.alpn_protocols = Vec::from(protocols);

    config
}
