use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Generate sing-box config files", long_about = None)]
pub struct Args {
    #[arg(short, long, help = "Generator config, accept file path or URL")]
    pub generator: String,

    #[arg(short, long, help = "Emit debug log")]
    pub verbose: bool,

    #[arg(short, long, help = "Config output path")]
    pub output_path: String,
}
