use std::fmt::Debug;
use clap::Parser;

use dns_resolver::client;

#[derive(Parser, Debug)]
struct Options {
    /// Host name that is needed to resolve
    host: String,
}

fn main() {
    spdlog::default_logger().set_level_filter(spdlog::LevelFilter::Equal(spdlog::Level::Info));
    let options = Options::parse();
    let dns_client = client::DnsClient::new();
    dns_client.ask(&options.host);
}