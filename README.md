# Spire Workload

This crate provides a number of useful APIs to help Rust programs use Spire workload API:

- `SpiffeID` and `SpiffeIDMatcher` help parse a Spiffe ID and match against pre-defined patterns

- `init` function helps a workload talk to spire agent and fetch its identity

- `make_client_config` and `make_server_config` helps generate `rustls::ClientConfig` and `rustls::ServerConfig` respectively. These configs support hot reloading of spire provided identites and verify spiffe ID during TLS handshake.

## Examples

1. `examples/dump.rs` shows how to use spire-workload to dump current identities cached by spire agent

2. `examples/verify_jwt.rs` shows how to verify a spire issued JWT token with spire agent.

## License

Apache 2.0
