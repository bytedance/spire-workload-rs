use super::{SpiffeIdAuthorizer, IDENTITIES};
use crate::pki;
use crate::SpiffeID;
use log::*;
use rustls::client::ServerCertVerified;
use rustls::server::ClientCertVerified;
use rustls::sign::CertifiedKey;
use rustls::{Certificate, Error, RootCertStore, ServerName};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::SystemTime;
use webpki::{TLSClientTrustAnchors, TLSServerTrustAnchors};

pub(crate) struct DynamicLoadedCertResolverVerifier {
    pub(crate) identity: Option<SpiffeID>,
    pub(crate) authorizer: Box<dyn SpiffeIdAuthorizer>,
    pub(crate) require_client_auth: bool,
}

impl DynamicLoadedCertResolverVerifier {
    fn resolve_cert_key(&self) -> Option<Arc<CertifiedKey>> {
        let identities = IDENTITIES.load();
        let identity = match self.identity.as_ref() {
            Some(identity) => identities.get(identity),
            None => identities.iter().next().map(|x| x.1),
        };
        match identity {
            Some(identity) => Some(identity.cert_key.clone()),
            None => {
                match self.identity.as_ref() {
                    Some(identity) => error!(
                        "the identity '{}' has disappeared! serving no peer certificate.",
                        identity
                    ),
                    None => error!("no identities are available! serving no peer certificate."),
                }
                None
            }
        }
    }

    fn resolve_roots(&self) -> Option<Arc<RootCertStore>> {
        let identities = IDENTITIES.load();
        let identity = match self.identity.as_ref() {
            Some(identity) => identities.get(identity),
            None => identities.iter().next().map(|x| x.1),
        };
        match identity {
            Some(identity) => Some(identity.bundle.clone()),
            None => {
                match self.identity.as_ref() {
                    Some(identity) => error!("the bundle accompanying identity '{}' has disappeared! rejecting all peer connections.", identity),
                    None => error!("no identities are available! rejecting all peer connections."),
                }
                None
            }
        }
    }

    fn resolve_raw_root_bundle(&self) -> Option<Vec<Vec<u8>>> {
        let identities = IDENTITIES.load();
        let identity = match self.identity.as_ref() {
            Some(identity) => identities.get(identity),
            None => identities.iter().next().map(|x| x.1),
        };
        match identity {
            Some(identity) => Some(identity.raw_bundle.clone()),
            None => {
                match self.identity.as_ref() {
                    Some(identity) => error!("the bundle accompanying identity '{}' has disappeared! rejecting all peer connections.", identity),
                    None => error!("no identities are available! rejecting all peer connections."),
                }
                None
            }
        }
    }
}

impl rustls::client::ResolvesClientCert for DynamicLoadedCertResolverVerifier {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.resolve_cert_key().map(|x| Arc::new((&*x).clone()))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for DynamicLoadedCertResolverVerifier {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        self.resolve_cert_key().map(|x| Arc::new((&*x).clone()))
    }
}

impl rustls::server::ClientCertVerifier for DynamicLoadedCertResolverVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(self.require_client_auth)
    }

    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        let roots = self.resolve_roots();
        roots.map(|x| x.subjects())
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> StdResult<rustls::server::ClientCertVerified, Error> {
        let roots = match self.resolve_roots() {
            Some(x) => x,
            None => {
                return Err(Error::General(
                    "no identities are available, try again later".to_string(),
                ));
            }
        };
        let raw_roots_bundle = match self.resolve_raw_root_bundle() {
            Some(x) => x,
            None => {
                return Err(Error::General(
                    "no identities are available, try again later".to_string(),
                ))
            }
        };

        let (cert, chain, trustroots) =
            pki::prepare(&*roots, &raw_roots_bundle, end_entity, intermediates)?;
        let time = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;
        cert.verify_is_valid_tls_client_cert(
            pki::SUPPORTED_SIG_ALGS,
            &TLSClientTrustAnchors(&trustroots),
            &chain,
            time,
        )
        .map_err(|_| Error::General(webpki::Error::InvalidCertValidity.to_string()))?;
        if intermediates.len() == 0 && end_entity.0.is_empty() {
            return Err(Error::General(
                webpki::Error::ExtensionValueInvalid.to_string(),
            ));
        }
        let spiffe_id = SpiffeID::raw_from_x509_der(&end_entity.0)
            .map_err(|_| Error::General(webpki::Error::ExtensionValueInvalid.to_string()))?;
        if !self.authorizer.validate_raw(&spiffe_id) {
            return Err(Error::General(
                webpki::Error::ExtensionValueInvalid.to_string(),
            ));
        }

        Ok(ClientCertVerified::assertion())
    }
}

impl rustls::client::ServerCertVerifier for DynamicLoadedCertResolverVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a trusted `RootCertStore` CA
    /// - Not Expired
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        _now: SystemTime,
    ) -> StdResult<ServerCertVerified, Error> {
        let roots = match self.resolve_roots() {
            Some(x) => x,
            None => {
                return Err(Error::General(
                    "no identities are available, try again later".to_string(),
                ));
            }
        };
        let raw_roots_bundle = match self.resolve_raw_root_bundle() {
            Some(x) => x,
            None => {
                return Err(Error::General(
                    "no identities are available, try again later".to_string(),
                ))
            }
        };
        let (cert, chain, trustroots) =
            pki::prepare(&*roots, &raw_roots_bundle, end_entity, intermediates)?;
        let now = pki::try_now()?;
        cert.verify_is_valid_tls_server_cert(
            pki::SUPPORTED_SIG_ALGS,
            &TLSServerTrustAnchors(&trustroots),
            &chain,
            now,
        )
        .map_err(|_| Error::General(webpki::Error::InvalidCertValidity.to_string()))?;

        if !ocsp_response.is_empty() {
            debug!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        if intermediates.len() == 0 && end_entity.0.is_empty() {
            return Err(Error::General(
                webpki::Error::ExtensionValueInvalid.to_string(),
            ));
        }
        let spiffe_id = SpiffeID::raw_from_x509_der(&end_entity.0)
            .map_err(|_| Error::General(webpki::Error::ExtensionValueInvalid.to_string()))?;
        if !self.authorizer.validate_raw(&spiffe_id) {
            return Err(Error::General(
                webpki::Error::ExtensionValueInvalid.to_string(),
            ));
        }

        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
pub mod test {
    use super::super::*;
    use super::*;
    use rcgen::{Certificate, *};
    use rustls::sign::CertifiedKey;
    use rustls::PrivateKey;
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    pub fn make_ca() -> Certificate {
        let mut ca_cert = CertificateParams::new(vec![]);
        ca_cert.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Certificate::from_params(ca_cert).unwrap()
    }

    pub fn rustlsify(key: Vec<u8>, cert: Vec<u8>) -> CertifiedKey {
        CertifiedKey::new(
            vec![rustls::Certificate(cert)],
            rustls::sign::any_ecdsa_type(&PrivateKey(key))
                .map_err(|_| anyhow!("unsupport private key type"))
                .unwrap(),
        )
    }

    pub fn make_raw_identity(ca: &Certificate, spiffe_id: SpiffeID) -> (Vec<u8>, Vec<u8>) {
        let cert = CertificateParams::new(vec![spiffe_id.to_string()]);
        let cert = Certificate::from_params(cert).unwrap();
        (
            cert.serialize_private_key_der(),
            cert.serialize_der_with_signer(ca).unwrap(),
        )
    }

    lazy_static! {
        pub static ref CLIENT_SVID: SpiffeID = SpiffeID::new(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.spire_rs_client"
                .parse()
                .unwrap()
        )
        .unwrap();
        pub static ref SERVER_SVID: SpiffeID = SpiffeID::new(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.spire_rs_server"
                .parse()
                .unwrap()
        )
        .unwrap();
    }

    // this is racy
    pub fn mock_identity() {
        if IDENTITIES.load().len() != 0 {
            return;
        }
        let ca_cert = make_ca();
        let (server_key, server_cert) = make_raw_identity(&ca_cert, SERVER_SVID.clone());
        let (client_key, client_cert) = make_raw_identity(&ca_cert, CLIENT_SVID.clone());

        let mut root_store = RootCertStore { roots: vec![] };
        root_store
            .add(&rustls::Certificate(ca_cert.serialize_der().unwrap()))
            .unwrap();
        let root_store = Arc::new(root_store);

        let client_identity = Identity {
            cert_key: Arc::new(rustlsify(client_key.clone(), client_cert)),
            raw_key: client_key,
            raw_bundle: vec![ca_cert.serialize_der().unwrap()],
            bundle: root_store.clone(),
        };
        let server_identity = Identity {
            cert_key: Arc::new(rustlsify(server_key.clone(), server_cert)),
            raw_key: server_key,
            raw_bundle: vec![ca_cert.serialize_der().unwrap()],
            bundle: root_store,
        };
        let mut identities = BTreeMap::new();
        identities.insert(CLIENT_SVID.clone(), Arc::new(client_identity));
        identities.insert(SERVER_SVID.clone(), Arc::new(server_identity));
        if IDENTITIES.load().len() != 0 {
            return;
        }
        init_mock(identities, vec![]);
    }

    #[tokio::test]
    async fn round_trip_test() {
        mock_identity();
        let addr = "127.0.0.1:8765".parse::<SocketAddr>().unwrap();
        let listener = TcpListener::bind(addr.clone()).await.unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(make_server_config(
            Some(SERVER_SVID.clone()),
            &[],
            Box::new(CLIENT_SVID.clone()),
            true,
        )));
        // accept connections and process them

        tokio::spawn(async move {
            // pass test
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.clone().accept(stream).await.unwrap();

            // fail test
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.clone().accept(stream).await.unwrap_err();

            // pass test
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.clone().accept(stream).await.unwrap();
        });
        let servername: rustls::ServerName = "spiffe-test".try_into().unwrap();
        // pass test
        {
            let config = TlsConnector::from(Arc::new(make_client_config(
                Some(CLIENT_SVID.clone()),
                &[],
                Box::new(SERVER_SVID.clone()),
                true,
            )));

            let stream = TcpStream::connect(addr.clone()).await.unwrap();
            let _ = config.connect(servername.clone(), stream).await.unwrap();
        }
        // pass test
        {
            let config = TlsConnector::from(Arc::new(make_client_config(
                Some(SERVER_SVID.clone()),
                &[],
                Box::new(SERVER_SVID.clone()),
                true,
            )));

            let stream = TcpStream::connect(addr.clone()).await.unwrap();
            let _ = config.connect(servername.clone(), stream).await.unwrap();
        }
        // fail test
        {
            let config = TlsConnector::from(Arc::new(make_client_config(
                Some(CLIENT_SVID.clone()),
                &[],
                Box::new(CLIENT_SVID.clone()),
                true,
            )));

            let stream = TcpStream::connect(addr.clone()).await.unwrap();
            let _ = config
                .connect(servername.clone(), stream)
                .await
                .unwrap_err();
        }
    }
}
