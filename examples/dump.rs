use anyhow::*;
use spire_workload::{init, wait_for_identity_update, Identity, SpiffeID, IDENTITIES, JWT_BUNDLES};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;

fn format_pem(typ: &str, data: &[u8]) -> String {
    format!(
        "-----BEGIN {}-----\n{}-----END {}-----",
        typ,
        data.chunks(48)
            .map(|c| base64::encode(c) + "\n")
            .collect::<Vec<String>>()
            .join(""),
        typ,
    )
}

fn filter_component(component: &str) -> String {
    component.replace("..", "-")
}

async fn write_identity<T: AsRef<Path>>(
    svid: &SpiffeID,
    identity: &Arc<Identity>,
    dir: T,
) -> Result<()> {
    let raw_bundle = identity
        .raw_bundle
        .iter()
        .map(|cert| format_pem("CERTIFICATE", &cert[..]))
        .collect::<Vec<String>>()
        .join("\n");
    fs::write(dir.as_ref().join("bundle.pem"), raw_bundle.as_bytes()).await?;

    let raw_certificate = identity
        .cert_key
        .cert
        .iter()
        .map(|cert| format_pem("CERTIFICATE", &cert.0[..]))
        .collect::<Vec<String>>()
        .join("\n");
    fs::write(
        dir.as_ref().join("certificate.pem"),
        raw_certificate.as_bytes(),
    )
    .await?;

    let raw_key = format_pem("PRIVATE KEY", &identity.raw_key[..]);
    fs::write(dir.as_ref().join("key.pem"), raw_key.as_bytes()).await?;

    fs::write(dir.as_ref().join("spiffe_id"), svid.to_string().as_bytes()).await?;
    Ok(())
}

async fn write_qualified_identity<T: AsRef<Path>>(
    svid: &SpiffeID,
    identity: &Arc<Identity>,
    dir: T,
) -> Result<()> {
    let path = dir
        .as_ref()
        .join(filter_component(svid.get_trust_domain()))
        .join(filter_component(
            &*svid
                .get_components()
                .iter()
                .map(|(name, value)| format!("{}:{}", name, value))
                .collect::<Vec<String>>()
                .join("~"),
        ));
    fs::create_dir_all(&path).await?;
    write_identity(svid, identity, &path).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    init();
    let env_spiffe_id = std::env::var("SPIFFE_ID")
        .ok()
        .filter(|t| !t.is_empty())
        .map(|t| {
            url::Url::parse(&*t)
                .map_err(Into::into)
                .and_then(SpiffeID::new)
                .expect("failed to parse SPIFFE_ID from environment")
        });

    let mut current_version = None::<u64>;
    loop {
        let identities = IDENTITIES.load();
        println!("updated identities: found {} identities", identities.len());
        for (svid, identity) in identities.iter() {
            println!("spiffe id: '{}'", svid);
            if let Some(env_spiffe_id) = env_spiffe_id.as_ref() {
                if env_spiffe_id == svid {
                    if let Err(e) = write_identity(svid, identity, ".").await {
                        eprintln!("failed to write svid: {:?}", e);
                    }
                }
            } else if let Err(e) = write_qualified_identity(svid, identity, ".").await {
                eprintln!("failed to write svid: {:?}", e);
            }
        }
        let jwt_bundles = JWT_BUNDLES.load();
        for (trust_domain, bundle) in jwt_bundles.iter() {
            if let Err(e) = fs::write(
                &*format!("bundle_{}.json", trust_domain.replace("/", "_")),
                format!("{}", bundle).as_bytes(),
            )
            .await
            {
                eprintln!("failed to write jwt bundle: {:?}", e);
            }
        }
        current_version = wait_for_identity_update(current_version).await;
        if current_version.is_none() {
            eprintln!("spire workload stopped, killing dumper...");
            break;
        }
    }
}
