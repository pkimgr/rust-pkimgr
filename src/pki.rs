use std::fs::{ File, create_dir_all };
use std::path::Path;
use std::{
    io::{ Error, Write },
    collections::HashMap,
};

use openssl::{
    pkey::Private,
    rsa::Rsa,
    x509::X509
};

use serde_json::to_string_pretty;

use crate::certificates::{
    CertArgs,
    PrivateKeyEnums,
    PrivateKeyEnums::PrivateRsa,
    CertBuilders,
};
use crate::pki_serializer::SerializedPki;

const PEM_DIR: &'static str = "private";
const CERTS_DIR: &'static str = "certs";

pub struct Pki <'a> {
    authorities: HashMap<String, (X509, PrivateKeyEnums)>,
    certs: HashMap<String, (X509, PrivateKeyEnums)>,
    path: &'a Path,
    cert_builders: &'a CertBuilders<'a>,
    serializer: SerializedPki
}

impl <'a> Pki<'a> {
    pub fn new(builders: &'a CertBuilders, path: &'a Path) -> Result<Pki<'a>, Error> {
        if !Path::exists(path) {
            create_dir_all(Path::join(path, PEM_DIR))?;
            create_dir_all(Path::join(path, CERTS_DIR))?;
        } else {
            // TODO load PKI
        }

        Ok(Pki {
            authorities: HashMap::new(),
            certs: HashMap::new(),
            path,
            cert_builders: &builders,
            serializer: SerializedPki::new()
        })
    }

    pub fn add_rsa_authority(&mut self, length: u32, name: &String) -> Result<&Self, Error> {
        // TODO Add Subauth
        let key: Rsa<Private> = Rsa::generate(length)?;

        let cert: X509 = self.cert_builders.generate_authority(
            CertArgs {
                authority_issuer: None,
                authority_pkey: None,
                key: PrivateRsa(key.to_owned()),
                name: name.to_owned(),
            }
        )?;

        self.write_files(name, cert.to_pem().unwrap(), key.private_key_to_pem().unwrap())?;

        self.authorities.insert(name.to_owned(), (cert, PrivateRsa(key)));
        self.serializer.add_certificate(name,name);

        Ok(self)
    }

    pub fn add_rsa_certificate(&mut self, length: u32, name: &String, authority_name: &String) -> Result<&Self, Error> {
        let key: Rsa<Private> = Rsa::generate(length)?;
        let authority: &(X509, PrivateKeyEnums) = self.authorities.get(authority_name).unwrap();

        let cert: X509 = self.cert_builders.generate_certificate(
            CertArgs {
                authority_issuer: Some(authority.0.subject_name()),
                authority_pkey: Some(authority.1.to_owned()),
                key: PrivateRsa(key.to_owned()),
                name: name.to_owned(),
            }
        )?;

        self.write_files(name, cert.to_pem().unwrap(), key.private_key_to_pem().unwrap())?;

        self.certs.insert(name.to_owned(), (cert, PrivateRsa(key)));
        self.serializer.add_certificate(name, authority_name);

        Ok(self)
    }

    pub fn get_authority_from_name(self: &Self, cert_name: &String) -> Option<&(X509, PrivateKeyEnums)> {
        self.authorities.get(cert_name)
    }

    pub fn save(self: &Self) -> Result<&Self, std::io::Error> {
        let mut metadata_file: File = File::create(Path::join(self.path, "metadata.json"))?;
        metadata_file.write_all(
            to_string_pretty(&self.serializer).unwrap().as_bytes()
        )?;

        Ok(self)
    }
    // Privates

    fn get_path(&self, to_join: &str) -> String {
        String::from(
            Path::join(self.path, to_join)
                .to_str()
                .unwrap_or("default")
        )
    }

    fn write_files(&self, name: &String, cert_pem: Vec<u8>, private_key: Vec<u8>) -> Result<(), Error> {
        let mut key_file: File = File::create(
            format!("{}/{}.pem", self.get_path(PEM_DIR), name)
        ).unwrap();
        let mut cert_file: File = File::create(
            format!("{}/{}.crt", self.get_path(CERTS_DIR), name)
        ).unwrap();

        key_file.write_all(&private_key)?;
        cert_file.write_all(&cert_pem)?;

        Ok(())
    }

    // fn save(&self) {


    // }
}