use rustls::{Certificate, Error, RootCertStore};

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
    webpki::Time::try_from(std::time::SystemTime::now()).map_err(|_| Error::FailedToGetCurrentTime)
}

pub fn prepare<'a, 'b>(
    _roots: &'b RootCertStore,
    raw_bundles: &'b Vec<Vec<u8>>,
    end_entity: &'a Certificate,
    intermediates: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, Error> {
    if intermediates.is_empty() || end_entity.0.is_empty() {
        return Err(Error::NoCertificatesPresented);
    }
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&end_entity.0)
        .map_err(|_| Error::InvalidCertificateData("Invalid Cert".to_owned()))?;

    let chain: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

    // since the OwnedTrustAnchor::to_trust_anchor is private,
    // need to use webpki::cert_der_as_trust_anchor to parse from Vec<u8> again
    let trustroots = raw_bundles
        .iter()
        .filter_map(|x| webpki::trust_anchor_util::cert_der_as_trust_anchor(&x).ok())
        .collect();

    Ok((cert, chain, trustroots))
}
