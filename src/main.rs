use std::{
    fs,
    path::Path
};

use pkimgr::certificates::CertBuilders;
use serde_json::Result;
use clap::Parser;

use pkimgr::{BANNER,
    configuration::{Configuration, DEFAULT_CONFIGURATION}
};
use pkimgr::Pkimgr;

/// Simple PKI generator
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// Path to store the PKI
    #[arg(short, long, default_value = "output")]
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

    let args: Args = Args::parse();

    let config_str: String = match args.configuration_file.is_empty() {
        true => DEFAULT_CONFIGURATION.to_string(),
        false => fs::read_to_string(args.configuration_file).expect("Cannot read configuration file")
    };

    let mut manager: Pkimgr = Pkimgr::new();

    let conf: Configuration = serde_json::from_str(&config_str)?;
    let cert_builders: CertBuilders = CertBuilders::new(conf);

    let path = Path::new(&args.path).join("first");
    manager.new_pki(path.as_path(), &cert_builders);
    dbg!(manager.list_pki().keys());

    Ok(())
}