use std::{
    collections::HashMap,
    fs::{ create_dir_all, File },
    io::{ Error, ErrorKind, Write },
    path::{Path, PathBuf}
};

use openssl::x509::X509;
use log::{info, debug};
use serde::{Serialize, Deserialize};
use serde_json::to_string_pretty;

use crate::{
    certificates::{
        x509::{x509_to_certificate, generate_authority, generate_certificate},
        CertArgs,
        Certificate
    },
    configuration::Configuration,
    key::Key,
    CERTS_DIR,
    PEM_DIR
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PkiJSON {
    pub pki_name: String,
    pub root: Certificate
}

#[derive(Clone)]
pub struct Pki {
    authorities: HashMap<String, (X509, Key)>,
    certs: HashMap<String, (X509, Key)>,
    path: PathBuf,
    json: PkiJSON,
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
            json: PkiJSON {
                pki_name: filename,
                root: Certificate::default()
            },
            configuration
        })
    }

    pub fn get_configuration(self: &Self) -> Configuration {
        self.configuration.clone()
    }

    pub fn get_path(self: &Self) -> PathBuf {
        self.path.clone()
    }

    pub fn add_authority(self: &mut Self, name: &String, auth_name: Option<&String>, key: Key) -> Result<&Self, Error> {
        let (authority_issuer, authority_pkey) = match auth_name {
            Some(name) => {
                let (cert, key) = self.get_authority(name)?;

                (Some(cert.subject_name().to_owned()?), Some(key.to_owned()))
            },
            None => (None, None)
        };

        info!("{} {}", &authority_issuer.is_none(), name);

        let cert = generate_authority(
            CertArgs {
                authority_issuer,
                authority_pkey,
                key: key.clone(),
                name: name.to_owned(),
                cert_entries: self.configuration.x509_certs_entries.clone()
            }
        )?;

        if auth_name.is_none() {
            self.json.root = x509_to_certificate(&cert, &key).clone();
        } else {
            serialize(
                &mut self.json.root,
                &x509_to_certificate(&cert, &key),
                &name,
                &auth_name.unwrap_or(&name),
                &key
            );
        }

        self.authorities.insert(name.to_owned(), (cert.clone(), key));

        Ok(self)
    }

    pub fn add_certificate(self: &mut Self, name: &String, auth_name: &String, key: Key) -> Result<&Self, Error> {
        let (issuer_cert, issuer_key) = self.get_authority(auth_name)?;

        let cert = generate_certificate(
            CertArgs {
                authority_issuer: Some(issuer_cert.subject_name().to_owned()?),
                authority_pkey: Some(issuer_key.to_owned()),
                key: key.clone(),
                name: name.to_owned(),
                cert_entries: self.configuration.x509_certs_entries.clone()
            }
        )?;

        serialize(
            &mut self.json.root,
            &x509_to_certificate(&cert, &key),
            &name,
            &auth_name,
            &key
        );

        self.certs.insert(name.to_owned(), (cert.clone(), key));

        Ok(self)

    }

    pub fn save(self: &Self) -> Result<&Self, Error> {
        let mut metadata_file: File = File::create(Path::join(self.path.as_ref(), "metadata.json"))?;
        metadata_file.write_all(
            to_string_pretty(&self.json)?.as_bytes()
        )?;

        for (name, (cert, key)) in self.authorities.iter() {
            self.write_files(name, cert.to_pem()?, key.to_pem()?)?;
        }

        for (name, (cert, key)) in self.certs.iter() {
            self.write_files(name, cert.to_pem()?, key.to_pem()?)?;
        }

        Ok(self)
    }

    // Privates
    fn get_authority(self: &mut Self, name: &String) -> Result<&(X509, Key), Error> {
        self.authorities.get(name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("Authority {} not found", name)))
    }

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

fn serialize(root: &mut Certificate, cert: &Certificate, cname: &String, auth_cname: &String, key: &Key) -> bool {
    if root.cname == *auth_cname {
        root.subcerts.push(cert.clone());
        return true;
    }

    for subcert in root.subcerts.iter_mut() {
        if serialize(subcert, cert, cname, auth_cname, key) {
            return true;
        }
    }

    false
}
