use super::workload::*;
use super::Identity;
use crate::SpiffeID;
use anyhow::*;
use log::*;
use rustls::sign::CertifiedKey;
use rustls::{Certificate, PrivateKey, RootCertStore};
use std::sync::Arc;

// splits concatenated DER files (why doesn't rustls/webpki do this?)
pub fn split_der(der_blob: &[u8]) -> Result<Vec<&[u8]>> {
    let mut index = 0usize;
    let mut start_index = 0usize;
    let mut results = vec![];
    while index < der_blob.len() {
        if der_blob[index] != 0x30 {
            // class: universal
            // p/c: primitive
            // tag: BMPString
            return Err(anyhow!("not a valid form ASN.1 PEM file"));
        }
        index += 1;
        if index >= der_blob.len() {
            return Err(anyhow!("not a valid form ASN.1 PEM file"));
        }
        let len_base = der_blob[index];
        index += 1;
        let len = if (len_base & 0x80) == 0 {
            // short form
            len_base as usize
        } else {
            // long form
            // len_base here is the length of our length
            let len_base = (len_base & 0x7F) as usize;
            if index + len_base > der_blob.len() || len_base > 8 {
                return Err(anyhow!("not a valid form ASN.1 PEM file"));
            }
            let len_octets = &der_blob[index..index + len_base];
            index += len_base;

            let mut len_octets_padded: [u8; 8] = [0; 8];
            len_octets_padded[8 - len_octets.len()..].copy_from_slice(len_octets);
            u64::from_be_bytes(len_octets_padded) as usize
        };
        if index + len > der_blob.len() {
            return Err(anyhow!("truncated ASN.1 PEM file"));
        }

        let content = &der_blob[start_index..index + len];
        start_index = match index.checked_add(len) {
            Some(s) => s,
            None => {
                return Err(anyhow!("invalid metadata!"));
            }
        };
        index = start_index;
        results.push(content);
    }
    Ok(results)
}

pub fn parse_der_cert_chain(der_blob: &[u8]) -> Result<Vec<Certificate>> {
    Ok(split_der(der_blob)?
        .into_iter()
        .map(|x| Certificate(x.to_owned()))
        .collect())
}

pub fn svid_to_identity(svid: X509svid) -> Result<(SpiffeID, Arc<Identity>)> {
    let certs = parse_der_cert_chain(&svid.x509_svid[..])?;
    let key = PrivateKey(svid.x509_svid_key);
    let bundle = parse_der_cert_chain(&svid.bundle[..])?;
    if svid.federates_with.len() != 0 {
        warn!(
            "found federation trust domain with our identity, this is not supported. SVID: {}",
            svid.spiffe_id
        );
    }
    let cert_key = CertifiedKey::new(
        certs,
        Arc::new(
            rustls::sign::any_supported_type(&key)
                .map_err(|_| anyhow!("unsupport private key type"))?,
        ),
    );
    let mut root_store = RootCertStore { roots: vec![] };
    for bundle_cert in bundle.iter() {
        root_store.add(bundle_cert)?;
    }
    Ok((
        SpiffeID::new(url::Url::parse(&svid.spiffe_id)?)?,
        Arc::new(Identity {
            cert_key: Arc::new(cert_key),
            raw_key: key.0,
            raw_bundle: bundle.into_iter().map(|x| x.0).collect(),
            bundle: Arc::new(root_store),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::test::*;
    use rcgen::*;

    #[test]
    fn test_split_der() {
        let cert1 = generate_simple_self_signed(vec![]).unwrap();
        let cert2 = generate_simple_self_signed(vec![]).unwrap();

        let key1 = cert1.serialize_private_key_der();
        let key2 = cert2.serialize_private_key_der();

        let mut concat = key1.clone();
        concat.extend_from_slice(&key2[..]);

        let split = split_der(&concat[..]).unwrap();
        assert_eq!(split.len(), 2);
        assert_eq!(split[0], &key1[..]);
        assert_eq!(split[1], &key2[..]);
    }

    #[test]
    fn test_svid_identity() {
        let ca_cert = make_ca();
        let (server_key, server_cert) = make_raw_identity(&ca_cert, SERVER_SVID.clone());

        let svid_raw = X509svid {
            spiffe_id: SERVER_SVID.to_string(),
            x509_svid: server_cert.clone(),
            x509_svid_key: server_key,
            bundle: ca_cert.serialize_der().unwrap(),
            federates_with: vec![],
        };

        let (spiffe_id, identity) = svid_to_identity(svid_raw).unwrap();
        assert_eq!(&spiffe_id, &*SERVER_SVID);
        let certs = &identity.cert_key.cert[..];
        assert_eq!(certs.len(), 1);
        assert_eq!(&certs[0].0, &server_cert);
    }
}
