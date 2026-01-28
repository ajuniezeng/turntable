#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::style)]

use clap::Parser;
use tracing::Level;
use turntable::cli::Args;
use turntable::generator::Generator;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let is_verbose = args.verbose;
    tracing_subscriber::fmt()
        .with_max_level(if is_verbose {
            Level::TRACE
        } else {
            Level::INFO
        })
        .init();

    if let Err(e) = run(args).await {
        tracing::error!("Error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    tracing::info!("Loading generator config from: {}", args.generator);

    let generator = Generator::load(&args.generator).await?;

    generator.generate_to_file(args.output.as_deref()).await?;

    tracing::info!("Config generation complete!");
    Ok(())
}
