use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Generate sing-box config files", long_about = None)]
pub struct Args {
    /// Config file for generating, default location `~/.config/turntable/generator.toml`
    #[arg(
        short,
        long,
        help = "Generator config, accept file path or URL",
        default_value_t = String::from(r#"~/.config/turntable/generator.toml"#)
    )]
    pub generator: String,

    /// Log level set to DEBUG
    #[arg(short, long, help = "Emit debug log")]
    pub verbose: bool,

    /// Override output file path
    #[arg(short, long, help = "Override config output path")]
    pub output: Option<String>,
}
