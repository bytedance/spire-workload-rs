use anyhow::{anyhow, Result};
use serde::{
    de::{Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::BTreeMap;
use std::fmt;
use url::Url;
use x509_parser::extensions::GeneralName;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpiffeID {
    trust_domain: String,
    components: BTreeMap<String, String>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub struct SpiffeIDMatcher {
    trust_domain: String,
    components: BTreeMap<String, Option<String>>,
}

impl Serialize for SpiffeIDMatcher {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let str_value: String = self.to_string();
        serializer.serialize_str(&*str_value)
    }
}

impl Serialize for SpiffeID {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let str_value: String = self.to_string();
        serializer.serialize_str(&*str_value)
    }
}

struct SpiffeVisitor;
impl<'de> Visitor<'de> for SpiffeVisitor {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a valid spiffe url",)
    }
}

impl<'de> Deserialize<'de> for SpiffeIDMatcher {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let url = Url::deserialize(deserializer)?;
        match SpiffeID::new(url) {
            Ok(x) => Ok(x.into()),
            Err(_) => Err(serde::de::Error::invalid_value(
                Unexpected::Str("url"),
                &SpiffeVisitor,
            )),
        }
    }
}

impl<'de> Deserialize<'de> for SpiffeID {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let url = Url::deserialize(deserializer)?;
        SpiffeID::new(url)
            .map_err(|_| serde::de::Error::invalid_value(Unexpected::Str("url"), &SpiffeVisitor))
    }
}

impl SpiffeID {
    pub fn raw_from_x509_der(x509: &[u8]) -> Result<String> {
        let (_, cert) = x509_parser::parse_x509_certificate(x509)?;
        let (_, subjects) = cert
            .tbs_certificate
            .subject_alternative_name()
            .ok_or_else(|| anyhow!("could not find subjectAlternativeName in certificate"))?;
        for subject in subjects.general_names.iter() {
            match subject {
                GeneralName::DNSName(uri) | GeneralName::URI(uri)
                    if uri.starts_with("spiffe://") =>
                {
                    return Ok(uri.to_string());
                }
                _ => continue,
            }
        }
        Err(anyhow!(
            "could not find SpiffeID in subjectAlternativeName of certificate"
        ))
    }

    pub fn from_x509_der(x509: &[u8]) -> Result<SpiffeID> {
        let raw = Self::raw_from_x509_der(x509)?;
        let url = Url::parse(&raw)?;
        SpiffeID::new(url)
    }

    pub fn new(url: Url) -> Result<SpiffeID> {
        if url.scheme() != "spiffe" {
            return Err(anyhow!(
                "invalid non-spiffe scheme in url: {}",
                url.scheme()
            ));
        }
        if url.username() != "" || url.password().is_some() {
            let mut url_sanitized = url;
            url_sanitized.set_username("<sanitized>").ok();
            url_sanitized.set_password(Some("<sanitized>")).ok();
            return Err(anyhow!(
                "cannot specify credentials in spiffe url: {:?}",
                url_sanitized
            ));
        }
        if url.query().is_some() {
            return Err(anyhow!("cannot specify query in spiffe url: {:?}", url));
        }
        if url.port().is_some() {
            return Err(anyhow!("cannot specify port in spiffe url: {:?}", url));
        }
        if url.fragment().is_some() {
            return Err(anyhow!("cannot specify fragment in spiffe url: {:?}", url));
        }
        if url.host_str().is_none() {
            return Err(anyhow!(
                "no trust_domain specified for spiffe url: {:?}",
                url
            ));
        }
        let trust_domain = url.host_str().unwrap();
        if trust_domain.len() > 255 {
            return Err(anyhow!("overlength trust domain (>255 bytes): {:?}", url));
        }
        let segments = url
            .path_segments()
            .map(|x| x.collect::<Vec<&str>>())
            .unwrap_or_default();
        let mut components: BTreeMap<String, String> = BTreeMap::new();
        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let split_index = segment.find(':');
            if split_index.is_none() {
                return Err(anyhow!("malformed component in spiffe url: '{}'", segment));
            }
            let split_index = split_index.unwrap();
            let name = &segment[0..split_index];
            let value = &segment[split_index + 1..];
            let current_value = components.get(name);
            if current_value.is_some() {
                return Err(anyhow!("invalid reset component in spiffe url: '{}'", name));
            }
            components.insert(name.to_string(), value.to_string());
        }

        // check if total length is no more than 2048
        let total_len = trust_domain.len()
            + 9 // len of "spiffe://"
            + components
                .iter()
                .fold(0, |acc, (k, v)| acc + k.len() + v.len() + 2); // + ':' '/'
        if total_len > 2048 {
            return Err(anyhow!("spiffe id too long! {} > 2048", total_len));
        }

        Ok(SpiffeID {
            trust_domain: trust_domain.to_string(),
            components,
        })
    }

    pub fn get_component<'a>(&'a self, name: &str) -> Option<&'a str> {
        self.components.get(name).map(|x| &**x)
    }

    pub fn get_components(&self) -> &BTreeMap<String, String> {
        &self.components
    }

    pub fn get_trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

impl fmt::Display for SpiffeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/{}",
            self.trust_domain,
            self.components
                .iter()
                .map(|(name, value)| format!("{}:{}", name, value))
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

impl fmt::Display for SpiffeIDMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/{}",
            self.trust_domain,
            self.components
                .iter()
                .map(|(name, value)| format!(
                    "{}:{}",
                    name,
                    value.as_ref().map(|x| &**x).unwrap_or("*")
                ))
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

impl From<SpiffeID> for SpiffeIDMatcher {
    fn from(spiffe_id: SpiffeID) -> SpiffeIDMatcher {
        SpiffeIDMatcher {
            trust_domain: spiffe_id.trust_domain,
            components: spiffe_id
                .components
                .into_iter()
                .map(|(key, value)| {
                    let value = if value == "*" { None } else { Some(value) };
                    (key, value)
                })
                .collect(),
        }
    }
}

impl SpiffeIDMatcher {
    #[allow(dead_code)] // TODO: remove
    pub fn new(url: Url) -> Result<SpiffeIDMatcher> {
        SpiffeID::new(url).map(|x| x.into())
    }

    // BHashMap is strictly ordered
    pub fn matches(&self, id: &SpiffeID) -> bool {
        let mut id_iter = id.components.iter();
        for (name, value) in self.components.iter() {
            if value.is_none() {
                continue;
            }
            let value = value.as_ref().unwrap();
            let id_value = loop {
                if let Some((id_name, id_value)) = id_iter.next() {
                    if id_name != name {
                        continue;
                    }
                    break id_value;
                }
                return false;
            };
            if value != id_value {
                return false;
            }
        }
        true
    }

    pub fn get_component<'a>(&'a self, name: &str) -> Option<Option<&'a str>> {
        self.components.get(name).map(|x| x.as_ref().map(|x| &**x))
    }

    pub fn get_components(&self) -> &BTreeMap<String, Option<String>> {
        &self.components
    }

    pub fn get_trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_matcher_basic() -> Result<()> {
        SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)?;
        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_wildcard() -> Result<()> {
        let matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:*/r:us/vdc:*/id:security.platform.kms_client",
        )?)?;
        assert_eq!(matcher.components.get("ns").unwrap(), &None::<String>);
        assert_eq!(matcher.components.get("r").unwrap().as_ref().unwrap(), "us");
        assert_eq!(matcher.components.get("vdc").unwrap(), &None::<String>);
        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_serialization() -> Result<()> {
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:*/id:security.platform.kms_client",
        )?)?;
        let serialized = serde_json::to_string(&spiffe_matcher)?;
        let deserialized: SpiffeIDMatcher = serde_json::from_str(&serialized)?;
        assert_eq!(spiffe_matcher, deserialized);
        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_matching() -> Result<()> {
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:*/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(Url::parse("spiffe://spiffe-test/ns:tce/r:us/vdc:a_vdc/new:test/id:security.platform.kms_client").unwrap()).unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:us/vdc:a_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/r:us/vdc:a_vdc/id:security.platform.kms_client/ns:tce",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:us/vdc:another_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:d/test:*/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse("spiffe://spiffe-test/ns:tce/r:us/vdc:d/id:security.platform.kms_client")
                .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:/vdc:*/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse("spiffe://spiffe-test/ns:tce/r:/vdc:a_vdc/id:security.platform.kms_client")
                .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));

        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_not_matching() -> Result<()> {
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:*/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:not_us/vdc:a_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(
            Url::parse("spiffe://spiffe-test/ns:tce/r:/vdc:a_vdc/id:security.platform.kms_client")
                .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(Url::parse("spiffe://spiffe-test/ns:tce/r:not_us/vdc:another_vdc/id:security.platform.kms_client").unwrap()).unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:/vdc:*/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:not_us/vdc:a_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(Url::parse("spiffe://spiffe-test/ns:tce/r:not_us/vdc:another_vdc/id:security.platform.kms_client").unwrap()).unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_not_matching_extra_field() -> Result<()> {
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:*/id:security.platform.kms_client/new:test",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:us/vdc:a_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        let test_spiffe = SpiffeID::new(
            Url::parse(
                "spiffe://spiffe-test/ns:tce/r:us/vdc:another_vdc/id:security.platform.kms_client",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        Ok(())
    }

    #[test]
    fn test_spiffe_matcher_matching_wildcard() -> Result<()> {
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:*/r:us/vdc:d/id:security.platform.kms_client",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse("spiffe://spiffe-test/ns:tce/r:us/vdc:d/id:security.platform.kms_client")
                .unwrap(),
        )
        .unwrap();
        assert!(spiffe_matcher.matches(&test_spiffe));
        let spiffe_matcher = SpiffeIDMatcher::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:d/id:*/new:test",
        )?)?;
        let test_spiffe = SpiffeID::new(
            Url::parse("spiffe://spiffe-test/ns:tce/r:us/vdc:d/id:security.platform.kms_client")
                .unwrap(),
        )
        .unwrap();
        assert!(!spiffe_matcher.matches(&test_spiffe));
        Ok(())
    }

    #[test]
    fn test_spiffe_basic() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)?;
        Ok(())
    }

    #[test]
    fn test_long_trust_domain() -> Result<()> {
        let trust_domain = vec!['a' as u8; 255];
        let trust_domain = std::str::from_utf8(&trust_domain).unwrap();
        let test_id = "spiffe://".to_string() + trust_domain;
        SpiffeID::new(Url::parse(&test_id)?)?;

        let trust_domain = vec!['a' as u8; 256];
        let trust_domain = std::str::from_utf8(&trust_domain).unwrap();
        let test_id = "spiffe://".to_string() + trust_domain;
        SpiffeID::new(Url::parse(&test_id)?).unwrap_err();

        Ok(())
    }

    #[test]
    fn test_long_spiffe_id() -> Result<()> {
        let trust_domain = vec!['x' as u8; 37];
        let trust_domain = std::str::from_utf8(&trust_domain).unwrap();
        let key = vec!['a' as u8; 1000];
        let key = std::str::from_utf8(&key).unwrap();
        let value = vec!['b' as u8; 1000];
        let value = std::str::from_utf8(&value).unwrap();
        let test_id = format!("spiffe://{}/{}:{}", trust_domain, key, value);
        SpiffeID::new(Url::parse(&test_id)?)?;

        let value = vec!['b' as u8; 1001];
        let value = std::str::from_utf8(&value).unwrap();
        let test_id = format!("spiffe://{}/{}:{}", trust_domain, key, value);
        SpiffeID::new(Url::parse(&test_id)?).unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_trailing_slash() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client/",
        )?)?;
        Ok(())
    }

    #[test]
    fn test_spiffe_double_slash() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us//vdc:useast2a/id:security.platform.kms_client",
        )?)?;
        Ok(())
    }

    #[test]
    fn test_spiffe_component_new() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/t:y/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)?;
        Ok(())
    }

    #[test]
    fn test_spiffe_scheme() -> Result<()> {
        SpiffeID::new(Url::parse(
            "http://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)
        .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_credentials() -> Result<()> {
        let error = SpiffeID::new(Url::parse("spiffe://uSeRnAmE:pAsSwOrD@spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client")?).unwrap_err();
        let error = format!("{:?}", error);
        assert!(!error.contains("uSeRnAmE"));
        assert!(!error.contains("pAsSwOrD"));
        Ok(())
    }

    #[test]
    fn test_spiffe_query() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client?x=y",
        )?)
        .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_port() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test:8080/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)
        .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_fragment() -> Result<()> {
        SpiffeID::new(Url::parse("spiffe://spiffe-test/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client#fragment")?).unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_host() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe:/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)
        .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_component_malformed() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/nstce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)
        .unwrap_err();
        Ok(())
    }

    #[test]
    fn test_spiffe_component_reset() -> Result<()> {
        SpiffeID::new(Url::parse(
            "spiffe://spiffe-test/ns:tce/ns:tce/r:us/vdc:useast2a/id:security.platform.kms_client",
        )?)
        .unwrap_err();
        Ok(())
    }
}
