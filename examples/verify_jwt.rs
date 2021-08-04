use spire_workload::{init, wait_for_identity_update, JWT_BUNDLES};

#[tokio::main]
async fn main() {
    let args = std::env::args();
    let args = args.skip(1).collect::<Vec<String>>();
    if args.len() != 1 {
        eprintln!("Usage: verify_jwt <token>");
        return;
    }

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    init();

    let mut current_version = None::<u64>;
    loop {
        let bundles = JWT_BUNDLES.load();
        println!("updated bundles: found {} bundles", bundles.len());
        for (trust_domain, bundle) in bundles.iter() {
            match bundle.verify_spiffe_id(args.get(0).unwrap()) {
                Ok(svid) => {
                    println!("bundle under trust domain '{}': {}", trust_domain, svid);
                    return;
                }
                Err(e) => {
                    println!(
                        "bundle under trust domain '{}' failed to verify token: {:?}",
                        trust_domain, e
                    );
                }
            }
        }
        current_version = wait_for_identity_update(current_version).await;
        if current_version.is_none() {
            eprintln!("spire workload stopped, killing dumper...");
            break;
        }
    }
}
