fn main() {
    let builder = tonic_build::configure()
        .disable_package_emission()
        .build_server(false);
    let proto_path = std::path::Path::new("./proto/workload.proto");

    // directory the main .proto file resides in
    let proto_dir = proto_path
        .parent()
        .expect("proto file should reside in a directory");

    builder.compile(&[proto_path], &[proto_dir]).unwrap();
}
