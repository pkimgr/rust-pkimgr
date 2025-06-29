use std::{
    fs::{self, File},
    path::Path
};

use log::{info, error};
use clap::Parser;
use env_logger::{init_from_env, Env};

use pkimgr::{
    Configuration, DEFAULT_CONFIGURATION,
    cli::Pkimgr,
    BANNER
};

/// Simple PKI generator
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to store the PKI
    #[arg(short, long, default_value = ".")]
    path: String,
    /// Path of the configuration file to use
    #[arg(short, long, default_value = "")]
    configuration_file: String,
    /// Path of the file describing the PKI
    #[arg()]
    pki_file: String
}

pub fn main() ->  () {
    println!("{}", BANNER);

    init_from_env(
        Env::new().default_filter_or("info")
    );

    let args: Args = Args::parse();

    let config_str: String = match args.configuration_file.is_empty() {
        true => DEFAULT_CONFIGURATION.to_string(),
        false => fs::read_to_string(args.configuration_file).expect("Cannot read configuration file")
    };

    let configuration: Configuration = serde_json::from_str(&config_str)
        .unwrap_or_else(|err| {
             error!("Cannot parse configuration file: {}", err);
             std::process::exit(1);
        });

    let mut manager: Pkimgr = Pkimgr::new(
        configuration,
        Path::new(&args.path).into()
    );

    let pki_file: File = File::open(&args.pki_file).unwrap();

    info!("Using {} file to create PKI", args.pki_file);

    manager.create_from_file(pki_file)
        .unwrap_or_else(|err| {
            error!("{}", err);
            std::process::exit(1);
        });
}