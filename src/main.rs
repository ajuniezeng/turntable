#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::style)]
use std::process::exit;

use clap::Parser;
use tracing::{Level, debug, error};
use turntable::cli::Args;
use url::Url;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let is_verbose = args.verbose;
    tracing_subscriber::fmt()
        .with_max_level(if is_verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .init();
    if let Ok(generator_url) = Url::parse(&args.generator) {
        debug!(
            generator_url = String::from(generator_url),
            "Parsing generator...",
        );
    } else {
        error!(generator = args.generator, "Unsupported");
        exit(1);
    }
    println!("Hello, world!");
}
