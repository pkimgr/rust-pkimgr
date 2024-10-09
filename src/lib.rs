use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    path::Path
};

use configuration::Configuration;

use crate::pki::{
    Pki,
    serializer::Serializer
};

pub mod certificates;
pub mod configuration;
pub mod pki;

pub const BANNER: &str = r#"
           __                    __  ____      __         __
          / /__  ____ _____     /  |/  (_)____/ /_  ___  / /
     __  / / _ \/ __ `/ __ \   / /|_/ / / ___/ __ \/ _ \/ /
    / /_/ /  __/ /_/ / / / /  / /  / / / /__/ / / /  __/ /
    \____/\___/\__,_/_/ /_/  /_/  /_/_/\___/_/ /_/\___/_/
        ____  __ __ ____
       / __ \/ //_//  _/___ ___  ____ ______
      / /_/ / ,<   / // __ `__ \/ __ `/ ___/
     / ____/ /| |_/ // / / / / / /_/ / /
    /_/   /_/ |_/___/_/ /_/ /_/\__, /_/
          rust edition        /____/
"#;
const DEFAULT_KEYLEN: u32 = 4096;

#[derive(Clone)]
pub struct Pkimgr {
    default_conf: Box<Configuration>,
    base_path: Box<Path>,
    pki: HashMap<String, Pki>,
}


impl Pkimgr {
    pub fn new(configuration: Box<Configuration>, base_path: Box<Path>) ->  Pkimgr {
        Pkimgr {
            default_conf: configuration,
            // certs_builder,
            base_path,
            pki: HashMap::new()
        }
    }

    pub fn get_pki(self: &Self) -> Vec<&String> {
        self.pki.keys().collect()
    }

    pub fn new_pki(self: &mut Self, pki_name: &String, config: Option<Configuration>) -> &Self {
        let configuration = match config {
            None => self.default_conf.clone(),
            Some(c) => Box::new(c)
        };
        self.pki.insert(
            pki_name.to_owned(),
            Pki::new(
                self.base_path.join(pki_name).into(),
                configuration,
            ).expect("cannot create new pki")
        );

        self
    }

    pub fn add_authority(self: &mut Self, pki_name: &String, cert_name: &String, key_len: Option<u32>) -> &Self {
        self.pki.get_mut(pki_name)
            .unwrap()
            .add_rsa_authority(
                key_len.unwrap_or(DEFAULT_KEYLEN),
                cert_name,
            )
            .unwrap();

        self
    }

    pub fn add_certificate(self: &mut Self, pki_name: &String, cert_name: &String, authority_name: &String, key_len: Option<u32>) -> &Self {
        self.pki.get_mut(pki_name)
            .unwrap()
            .add_rsa_certificate(
                key_len.unwrap_or(DEFAULT_KEYLEN),
                cert_name,
                authority_name
            )
            .unwrap();

        self
    }

    pub fn parse_pki_file(self: &mut Self, pki_file: File) -> &Self {
        let pki_serialized: Serializer = serde_json::from_reader(
            BufReader::new(pki_file)
        ).unwrap();

        self.new_pki(&pki_serialized.pki_name, None);
        self.add_authority(
            &pki_serialized.pki_name,
            &pki_serialized.root.cname,
            pki_serialized.root.keylen
        );

        for cert in pki_serialized.root.subcerts {
            if cert.subcerts.len() == 0 {
                self.add_certificate(
                    &pki_serialized.pki_name,
                    &cert.cname,
                    &pki_serialized.root.cname,
                    cert.keylen
                );
            }
        }

        self
    }
}
