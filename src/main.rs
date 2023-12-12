use std::fs;
use std::path::Path;
use std::str::FromStr;
use pkimgr::certificates::CertBuilders;
use serde_json::Result;
use clap::Parser;

use pkimgr::{BANNER, Configuration, DEFAULT_CONFIGURATION};
use pkimgr::pki::Pki;

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

    let conf: Configuration = serde_json::from_str(&config_str)?;

    let cert_builders: CertBuilders = CertBuilders::new(conf);
    let mut new_pki: Pki = Pki::new(&cert_builders, Path::new(&args.path))
        .expect("Cannot instantiate PKI struct");

    let authority_name: String = String::from_str("authority").unwrap();
    new_pki.add_rsa_authority(2048, &authority_name).unwrap();

    let service_name: String = String::from_str("service").unwrap();
    new_pki.add_rsa_certificate(4096, &service_name, &authority_name).unwrap();

    let service_name: String = String::from_str("service2").unwrap();
    new_pki.add_rsa_certificate(4096, &service_name, &authority_name).unwrap();

    new_pki.save().unwrap();

    Ok(())
}