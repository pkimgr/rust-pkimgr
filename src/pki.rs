use std::fs::{ File, create_dir_all };
use std::path::{Path, PathBuf};
use std::{
    io::{ Error, Write },
    collections::HashMap,
};

use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

use log::{info, debug};

use serde_json::to_string_pretty;

use crate::certificates::x509::generate_certificate;
use crate::key::Key;
use crate::{
    certificates::{
        CertArgs,
        x509::generate_authority
    },
    configuration::Configuration,
    serializer::pki::PkiSerializer,
    PEM_DIR,
    CERTS_DIR
};

#[derive(Clone)]
pub struct Pki {
    authorities: HashMap<String, (X509, PKey<Private>)>,
    certs: HashMap<String, (X509, PKey<Private>)>,
    path: PathBuf,
    serializer: PkiSerializer,
    configuration: Configuration
}

impl Pki {
    pub fn new(path: PathBuf, configuration: Configuration) -> Result<Pki, Error> {
        if !Path::exists(path.as_ref()) {
            debug!("{} not found, create it", path.to_string_lossy());

            create_dir_all(Path::join(path.as_ref(), PEM_DIR))?;
            create_dir_all(Path::join(path.as_ref(), CERTS_DIR))?;
        } else {
            debug!("{} found, load it", path.to_string_lossy());
            // TODO load PKI
        }

        let filename = String::from(path.file_name().unwrap()
            .to_str().unwrap());

        info!("New pki on {} ready", path.to_string_lossy());
        Ok(Pki {
            authorities: HashMap::new(),
            certs: HashMap::new(),
            path,
            serializer: PkiSerializer::new(filename),
            configuration
        })
    }

    pub fn get_configuration(self: &Self) -> Configuration {
        self.configuration.clone()
    }

    pub fn get_path(self: &Self) -> PathBuf {
        self.path.clone()
    }

    pub fn add_authnority(self: &mut Self, name: &String, key: &dyn Key) -> Result<&Self, ErrorStack> {
        let cert = generate_authority(
            CertArgs {
                authority_issuer: None,
                authority_pkey: None,
                key,
                name: name.to_owned(),
                cert_entries: self.configuration.x509_certs_entries.clone()
            }
        )?;

        self.authorities.insert(name.to_owned(), (cert.clone(), key.get_private_key()?));

        let pem = cert.to_pem()?;
        self.write_files(name, pem, key.to_pem()?).expect("TODO better management of errors");

        Ok(self)
    }

    pub fn add_certificate(self: &mut Self, name: &String, authority_name: &String, key: &dyn Key) -> Result<&Self, Error> {


        let (issuer_cert, issuer_key) = self.authorities.get(authority_name)
            .ok_or_else(|| Error::new(std::io::ErrorKind::NotFound, format!("Authority {} not found", authority_name)))?;
        let cert = generate_certificate(
            CertArgs {
                authority_issuer: Some(issuer_cert.subject_name().to_owned()?),
                authority_pkey: Some(issuer_key.to_owned()),
                key,
                name: name.to_owned(),
                cert_entries: self.configuration.x509_certs_entries.clone()
            }
        )?;

        self.certs.insert(name.to_owned(), (cert.clone(), key.get_private_key()?));
        // self.serializer.add_certificate(name, authority_name, key.get_key_length());
        self.write_files(name, cert.to_pem()?, key.to_pem()?)?;

        Ok(self)

    }

    pub fn save(self: &Self) -> Result<&Self, std::io::Error> {
        let mut metadata_file: File = File::create(Path::join(self.path.as_ref(), "metadata.json"))?;
        metadata_file.write_all(
            to_string_pretty(&self.serializer).unwrap().as_bytes()
        )?;

        Ok(self)
    }
    // Privates

    fn join_path(self: &Self, to_join: &str) -> String {
        String::from(
            Path::join(self.path.as_path(), to_join)
                .to_str()
                .unwrap_or("default")
        )
    }

    fn write_files(self: &Self, name: &String, cert_pem: Vec<u8>, private_key: Vec<u8>) -> Result<(), Error> {
        let mut key_file: File = File::create(
            format!("{}/{}.pem", self.join_path(PEM_DIR), name)
        ).unwrap();
        let mut cert_file: File = File::create(
            format!("{}/{}.crt", self.join_path(CERTS_DIR), name)
        ).unwrap();

        key_file.write_all(&private_key)?;
        cert_file.write_all(&cert_pem)?;

        Ok(())
    }
}