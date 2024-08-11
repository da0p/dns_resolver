# DNS resolver

[![Build Status](https://github.com/da0p/dns_resolver/actions/workflows/ci.yml/badge.svg)](https://github.com/dns_resolver/dns_resolver/actions)

Resolving a host name following [RFC-1035](https://datatracker.ietf.org/doc/html/rfc1035)

# Installation

- Download or clone the project
- In the project directory, run
```rust
cargo build
```
- In order to resolve a host name, run
```rust
cargo run -- HOST_NAME
```
- In order to run the test
```rust
cargo test
```