use std::ffi::OsStr;
use std::fs::{create_dir, File};
use std::path::Path;
use std::{
    io::{Error, Write},
    collections::HashMap,
    vec::Vec,
};

use openssl::{
    pkey::Private,
    rsa::Rsa,
    x509::X509
};

use crate::keys::rsa::generate_rsa_key;
use crate::certificates::x509;

const PEM_DIR: &'static str = "private";
const CERTS_DIR: &'static str = "certs";

pub struct Pki<'a> {
    authority: HashMap<String, (X509, Rsa<Private>)>,
    certs: HashMap<String, (X509, Rsa<Private>)>,
    serial: u32,
    path: &'a Path,
}

impl <'a> Pki<'a> {
    pub fn new(path: &'a Path) -> Result<Pki<'a>, Error> {
        if ! Path::exists(path) {
            create_dir(path)?;
            create_dir(Path::join(path, PEM_DIR))?;
            create_dir(Path::join(path, CERTS_DIR))?;
        } else {
            // TODO PKI Load
        }

        Ok(Pki {
            authority: HashMap::new(),
            certs:HashMap::new(),
            serial: 0,
            path
        })
    }

    pub fn get_domain(&self) -> String {
        let filename: &OsStr = self.path.file_name().unwrap_or(OsStr::new(""));
        String::from(filename.to_str().unwrap_or(""))
    }

    pub fn add_authority(&self, length: u32, name: String) -> Result<&Self, &'static str> {
        let key: Rsa<Private> = generate_rsa_key(length);
        let private: Vec<u8> = key.private_key_to_pem().unwrap();
        let cert = x509::generate_rsa_authority(key, self.serial)?;

        let mut key_file = File::create(
            format!("{}/{}.pem", self.get_path(PEM_DIR), name)
        )
            .unwrap();
        let mut cert_file = File::create(
            format!("{}/{}.crt", self.get_path(CERTS_DIR), name)
        )
            .unwrap();

        key_file.write_all(&private).unwrap();
        cert_file.write_all(&cert.to_text().unwrap()).unwrap();

        Ok(self)
    }

    pub fn get_authorities(&self) -> Vec<&String> {
        self.authority
            .iter()
            .fold(Vec::new(), |mut acc, (k, _)| {acc.push(k); acc })
    }

    fn get_path(&self, to_join: &str) -> String {
        String::from(
            Path::join(self.path, to_join)
                .to_str()
                .unwrap_or("default")
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_authorities() {
        assert_eq!(1, 1);
    }
}