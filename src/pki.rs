use rustls::{Certificate, RootCertStore, Error};

pub type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);
pub type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

pub static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

pub fn try_now() -> Result<webpki::Time, Error> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| Error::FailedToGetCurrentTime)
}

pub fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    end_entity: &'a Certificate,
    intermediates: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, Error> {
    if intermediates.is_empty() || end_entity.0.is_empty() {
        return Err(Error::NoCertificatesPresented);
    }
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&end_entity.0).map_err(|_| Error::InvalidCertificateData("Invalid Cert".to_owned()))?;

    let chain: Vec<&'a [u8]> = intermediates
        .iter()
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> =
        roots.roots.iter().map(|r| r.to_trust_anchor()).collect();

    Ok((cert, chain, trustroots))
}
