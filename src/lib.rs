pub mod cli;
pub mod config;
pub mod generator;
pub mod parser;
pub mod transform;
pub mod webdav;

pub fn get_version() -> String {
    "0.4.0".to_string()
}
