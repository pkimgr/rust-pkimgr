use std::{
    fs::{self, File},
    path::Path
};

use log::info;
use serde_json::Result;
use clap::Parser;
use env_logger::{init_from_env, Env};

use pkimgr::{
    certificates::CertsBuilder,
    configuration::{Configuration, DEFAULT_CONFIGURATION},
    Pkimgr,
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

pub fn main() ->Result<()> {
    // TODO Log system to better output
    println!("{}", BANNER);

    init_from_env(
        Env::new().default_filter_or("info")
    );

    let args: Args = Args::parse();

    let config_str: String = match args.configuration_file.is_empty() {
        true => DEFAULT_CONFIGURATION.to_string(),
        false => fs::read_to_string(args.configuration_file).expect("Cannot read configuration file")
    };

    let conf: Configuration = serde_json::from_str(&config_str)?;
    let cert_builder: CertsBuilder = CertsBuilder::new(conf);

    let mut manager: Pkimgr = Pkimgr::new(
        Box::new(cert_builder),
        Path::new(&args.path).into()
    );

    let pki_file: File = File::open(&args.pki_file).unwrap();

    info!("Using {} file to create PKI", args.pki_file);
    manager.parse_pki_file(pki_file);

    Ok(())
}