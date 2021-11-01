use core::fmt;
use log::warn;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Error, Result};
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::{
    ec::{EcGroup, EcKey},
    pkey::Public,
};

use base64::decode_config as b64_dec;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::SpiffeID;

const SEGMENTS_COUNT: usize = 3;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct JwtKey {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,
}

#[derive(PartialEq, Debug)]
pub struct JwtBundle {
    pub inner: BTreeMap<String, JwtKey>,
}

impl fmt::Display for JwtBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}",
            serde_json::to_string(&self.inner).unwrap_or_default()
        )
    }
}

impl Serialize for JwtBundle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.inner.values())
    }
}

impl<'de> Deserialize<'de> for JwtBundle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Vec::<JwtKey>::deserialize(deserializer)?;
        Ok(JwtBundle {
            inner: raw.into_iter().map(|x| (x.key_id.clone(), x)).collect(),
        })
    }
}

impl JwtKey {
    pub fn as_openssl_public_key(&self) -> Result<EcKey<Public>> {
        let nid = match &*self.curve {
            "P-256" => Nid::X9_62_PRIME256V1,
            "P-384" => Nid::SECP384R1,
            _ => {
                return Err(anyhow!(
                    "invalid curve in jwt key '{}': {}",
                    self.key_id,
                    self.curve
                ))
            }
        };
        let group = EcGroup::from_curve_name(nid)?;

        let x = base64::decode_config(&self.x, base64::URL_SAFE)?;
        let x = BigNum::from_slice(&x[..])?;
        let y = base64::decode_config(&self.y, base64::URL_SAFE)?;
        let y = BigNum::from_slice(&y[..])?;
        Ok(EcKey::from_public_key_affine_coordinates(&group, &x, &y)?)
    }
}

#[derive(Deserialize, Serialize)]
struct JwtHeader {
    #[serde(rename = "alg")]
    algorithm: String,
    #[serde(rename = "kid")]
    key_id: String,
    typ: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JwtPayload {
    sub: SpiffeID,
}

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    aud: Vec<String>,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    sub: String,
}

impl JwtBundle {
    pub fn verify_token<T: DeserializeOwned>(&self, encoded_token: &str) -> Result<T> {
        // compatible with old SVID implementations
        let raw_segments: Vec<&str> = encoded_token.split('.').collect();
        if raw_segments.len() != SEGMENTS_COUNT {
            return Err(anyhow!("jwt token has incorrect amounts of segments"));
        }
        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let b64_to_json = |seg| -> Result<JsonValue, Error> {
            serde_json::from_slice(b64_dec(seg, base64::URL_SAFE_NO_PAD)?.as_slice())
                .map_err(Error::from)
        };
        let payload_json = b64_to_json(payload_segment)?;

        // parse jwt header
        let header = header_segment;
        let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
        let header: JwtHeader = serde_json::from_slice(&header[..])?;
        if header.typ != "JWT" {
            return Err(anyhow!("header 'typ' not 'JWT': {}", header.typ));
        }
        let key = self
            .inner
            .get(&header.key_id)
            .ok_or_else(|| anyhow!("key id '{}' not found in bundle", header.key_id))?;

        let ec_public_key = key.as_openssl_public_key()?;
        let public_key_pem =
            openssl::pkey::PKey::from_ec_key(ec_public_key)?.public_key_to_pem()?;
        let public_key_u8 = public_key_pem.as_slice();

        let validation = Validation {
            algorithms: vec![Algorithm::ES256, Algorithm::ES384],
            validate_exp: false, // delay the process of expiration
            ..Validation::default()
        };

        let token_data = match decode::<Claims>(
            encoded_token,
            &DecodingKey::from_ec_pem(public_key_u8)?,
            &validation,
        ) {
            Ok(c) => c,
            Err(err) => return Err(anyhow!("{:?} happened during decoding Jwt token", err)),
        };

        // process expiration here
        let start = SystemTime::now();
        let now = start.duration_since(UNIX_EPOCH)?;

        let now = now.as_secs() as usize;

        // pass when token expiration time now
        if token_data.claims.exp < now as usize {
            if token_data.claims.exp < (now - 86400) as usize {
                // return Error when token has already expired for 24 hours
                return Err(anyhow!("Token has expired for over 24 hours"));
            } else {
                warn!("Token is about to expire in 24 hours")
            }
        }

        Ok(serde_json::from_value(payload_json)?)
    }

    pub fn verify_spiffe_id(&self, encoded_token: &str) -> Result<SpiffeID> {
        let payload: JwtPayload = self.verify_token(encoded_token)?;
        Ok(payload.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_test::{assert_tokens, Token};

    impl Default for JwtKey {
        fn default() -> Self {
            JwtKey {
                key_type: String::from("JWT"),
                key_id: String::from("dummy_keyid"),
                curve: String::from("P-256"),
                x: String::from("ovsRfW7L2V8zyGyJkOLA_JlczbgssQ7JrVQ2pzS74QY"),
                y: String::from("kO_n1Pz9qbK8gNzfXA4Hfo1K11-Dyl1JilDFYltNyhw"),
            }
        }
    }

    impl Default for JwtBundle {
        fn default() -> Self {
            let jwt_key = JwtKey {
                ..JwtKey::default()
            };
            let mut bundle_inner = BTreeMap::new();
            bundle_inner.insert(String::from("dummy_keyid"), jwt_key);

            JwtBundle {
                inner: bundle_inner,
            }
        }
    }

    impl Default for Claims {
        fn default() -> Self {
            Claims {
                aud: vec![String::from("dummy_audience")],
                exp: 1753717118, // Mon Jul 28 2025 15:38:38 GMT+0000
                iat: None,
                iss: None,
                sub: String::from("spiffe://dummy.org/ns:dummy/id:dummy"),
            }
        }
    }

    struct Setup {
        bundle_p256: JwtBundle,
        bundle_p384: JwtBundle,
        bundle_invalid_curve: JwtBundle,
        token_p256: String,
        token_p384: String,
        token_wrong_sig: &'static str,
        token_invalid_segment_length: &'static str,
        token_invalid_header_type: String,
        token_invalid_key_id: String,
        token_expired: String,
        token_about_to_expire: String,
        token_with_issuer: String,
        token_with_iat: String,
    }

    impl Setup {
        fn new() -> Self {
            Self {
                bundle_p256: {
                    JwtBundle{
                        ..JwtBundle::default()
                    }
                },
                bundle_p384: {
                    let jwt_key = JwtKey{
                        x: String::from("_Ukg1KZI3nxFNp94Dt6Zh4sDFMBtsCOpFpHNBw0K_R4OSW2veXsCta-mIUfbKGr-"),
                        y: String::from("4fQDA18hHXcB3Z8Ld-h0GG7ZGDyZjhsez1AlJ7Swvd8ruXiC3cVpVt27UPIv0f70"),
                        curve: String::from("P-384"),
                        .. JwtKey::default()};
                    let mut bundle_inner = BTreeMap::new();
                    bundle_inner.insert(String::from("dummy_keyid"), jwt_key);
                    JwtBundle{
                        inner: bundle_inner,
                    }
                },
                bundle_invalid_curve: {
                    let jwt_key = JwtKey{
                        x: String::from("_Ukg1KZI3nxFNp94Dt6Zh4sDFMBtsCOpFpHNBw0K_R4OSW2veXsCta-mIUfbKGr-"),
                        y: String::from("4fQDA18hHXcB3Z8Ld-h0GG7ZGDyZjhsez1AlJ7Swvd8ruXiC3cVpVt27UPIv0f70"),
                        curve: String::from("P-521"),
                        .. JwtKey::default()};
                    let mut bundle_inner = BTreeMap::new();
                    bundle_inner.insert(String::from("dummy_keyid"), jwt_key);
                    JwtBundle{
                        inner: bundle_inner,
                    }
                },
                token_p256: {
                    generate_token_on_algorithm(Algorithm::ES256)
                },
                token_p384: {
                    generate_token_on_algorithm(Algorithm::ES384)
                },
                token_wrong_sig: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImR1bW15X2tleWlkIn0.eyJhdWQiOlsiZHVtbXlfYXVkaWVuY2UiXSwiZXhwIjoxNzUzNzE3MTE4LCJpYXQiOjE2MjcwMTUyMjIsImlzcyI6InVzZXIiLCJzdWIiOiJzcGlmZmU6Ly9kdW1teS5vcmcvbnM6ZHVtbXkvaWQ6ZHVtbXkifQ.q7RMpz74PigIib2x34bSU6mp72Bw26tTS9Zl3nV_Gwzpt7-RsQFktbKefZC9JV0uJptCKJNLeyXBdNs3NgV7GA",
                token_invalid_segment_length: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImR1bW15X2tleWlkIn0",
                token_invalid_header_type: {
                    generate_token_wrong_header()
                },
                token_invalid_key_id: {
                    generate_token_invalid_key_id()
                },
                token_expired: {
                    let start = SystemTime::now();
                    let now = start.duration_since(UNIX_EPOCH).unwrap();
                    let expired_time = now.as_secs() as usize - 86460; // 24 hours plus 60 seconds so test can be consistent
                    generate_token_on_expire(expired_time)
                },
                token_about_to_expire: {
                    let start = SystemTime::now();
                    let now = start.duration_since(UNIX_EPOCH).unwrap();
                    let expired_time = now.as_secs() as usize - 46460;
                    generate_token_on_expire(expired_time)
                },
                token_with_issuer: {
                    generate_token_with_issuer()
                },
                token_with_iat: {
                    generate_token_with_iat()
                }
            }
        }
    }

    fn generate_token_on_algorithm(algorithm: Algorithm) -> String {
        let priv_key_pem = if algorithm == Algorithm::ES256 {
            include_bytes!("../tests/data/priv_key_256v1.pem").to_vec()
        } else {
            include_bytes!("../tests/data/priv_key_384r1.pem").to_vec()
        };

        let my_claims = Claims {
            ..Claims::default()
        };
        let header = Header {
            alg: algorithm,
            kid: Some("dummy_keyid".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem.as_slice()).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn generate_token_wrong_header() -> String {
        let priv_key_pem = include_bytes!("../tests/data/priv_key_256v1.pem");

        let my_claims = Claims {
            ..Claims::default()
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some("dummy_keyid".to_owned()),
            typ: Some("error".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn generate_token_invalid_key_id() -> String {
        let priv_key_pem = include_bytes!("../tests/data/priv_key_256v1.pem");

        let my_claims = Claims {
            ..Claims::default()
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some("error".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn generate_token_on_expire(expire_time: usize) -> String {
        let priv_key_pem = include_bytes!("../tests/data/priv_key_256v1.pem");

        let my_claims = Claims {
            exp: expire_time,
            ..Claims::default()
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some("dummy_keyid".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn generate_token_with_issuer() -> String {
        let priv_key_pem = include_bytes!("../tests/data/priv_key_256v1.pem");

        let my_claims = Claims {
            iss: Some(String::from("user")),
            ..Claims::default()
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some("dummy_keyid".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn generate_token_with_iat() -> String {
        let priv_key_pem = include_bytes!("../tests/data/priv_key_256v1.pem");

        let my_claims = Claims {
            iat: Some(1627015222), // Fri Jul 23 2021 04:40:22 GMT+0000
            ..Claims::default()
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some("dummy_keyid".to_owned()),
            ..Header::default()
        };

        let key = openssl::pkey::PKey::private_key_from_pem(priv_key_pem).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        encode(
            &header,
            &my_claims,
            &EncodingKey::from_ec_pem(pem.as_slice()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_verify_token_p256() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p256
                .verify_token::<JwtPayload>(&setup.token_p256)
                .is_ok(),
            "token verification failed"
        );
    }

    #[test]
    fn test_verify_token_p384() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p384
                .verify_token::<JwtPayload>(&setup.token_p384)
                .is_ok(),
            "token verification failed"
        );
    }

    #[test]
    fn test_verify_token_wrong_sig() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_p256
                    .verify_token::<JwtPayload>(setup.token_wrong_sig)
                    .unwrap_err()
            ),
            "Error(InvalidSignature) happened during decoding Jwt token"
        );
    }

    #[test]
    fn test_verify_token_bundle_invalid_curve() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_invalid_curve
                    .verify_token::<JwtPayload>(&setup.token_p256)
                    .unwrap_err()
            ),
            "invalid curve in jwt key 'dummy_keyid': P-521"
        );
    }

    #[test]
    fn test_verify_token_invalid_header_type() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_p256
                    .verify_token::<JwtPayload>(&setup.token_invalid_header_type)
                    .unwrap_err()
            ),
            "header 'typ' not 'JWT': error"
        );
    }

    #[test]
    fn test_verify_token_invalid_key_id() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_p256
                    .verify_token::<JwtPayload>(&setup.token_invalid_key_id)
                    .unwrap_err()
            ),
            "key id 'error' not found in bundle"
        );
    }

    #[test]
    fn test_verify_token_invalid_segment_length() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_p256
                    .verify_token::<JwtPayload>(setup.token_invalid_segment_length)
                    .unwrap_err()
            ),
            "jwt token has incorrect amounts of segments"
        );
    }

    #[test]
    fn test_verify_token_expired() {
        let setup = Setup::new();
        assert_eq!(
            format!(
                "{:#}",
                setup
                    .bundle_p256
                    .verify_token::<JwtPayload>(&setup.token_expired)
                    .unwrap_err()
            ),
            "Token has expired for over 24 hours"
        );
    }

    #[test]
    fn test_verify_token_about_to_expire() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p256
                .verify_token::<JwtPayload>(&setup.token_about_to_expire)
                .is_ok(),
            "Token about to expire verification failed"
        );
    }

    #[test]
    fn test_verify_token_with_issuer() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p256
                .verify_token::<JwtPayload>(&setup.token_with_issuer)
                .is_ok(),
            "Token with issuer verification failed"
        );
    }

    #[test]
    fn test_verify_token_with_iat() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p256
                .verify_token::<JwtPayload>(&setup.token_with_iat)
                .is_ok(),
            "Token with iat verification failed"
        );
    }

    #[test]
    fn test_verify_spiffe_id_p256() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p256
                .verify_spiffe_id(&setup.token_p256)
                .is_ok(),
            "Spiffe ID verification failed"
        );
    }

    #[test]
    fn test_verify_spiffe_id_p384() {
        let setup = Setup::new();
        assert!(
            setup
                .bundle_p384
                .verify_spiffe_id(&setup.token_p384)
                .is_ok(),
            "Spiffe ID verification failed"
        );
    }

    #[test]
    fn test_ser_de() {
        let setup = Setup::new();
        assert_tokens(
            &setup.bundle_p256,
            &[
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "JwtKey",
                    len: 5,
                },
                Token::String("kty"),
                Token::String("JWT"),
                Token::String("kid"),
                Token::String("dummy_keyid"),
                Token::String("crv"),
                Token::String("P-256"),
                Token::String("x"),
                Token::String("ovsRfW7L2V8zyGyJkOLA_JlczbgssQ7JrVQ2pzS74QY"),
                Token::String("y"),
                Token::String("kO_n1Pz9qbK8gNzfXA4Hfo1K11-Dyl1JilDFYltNyhw"),
                Token::StructEnd,
                Token::SeqEnd,
            ],
        );
    }

    #[test]
    fn test_jwt_bundle_display() {
        let setup = Setup::new();
        assert_eq!(format!("{}",setup.bundle_p256),String::from("{\"dummy_keyid\":{\"kty\":\"JWT\",\"kid\":\"dummy_keyid\",\"crv\":\"P-256\",\"x\":\"ovsRfW7L2V8zyGyJkOLA_JlczbgssQ7JrVQ2pzS74QY\",\"y\":\"kO_n1Pz9qbK8gNzfXA4Hfo1K11-Dyl1JilDFYltNyhw\"}}\n"));
    }
}
