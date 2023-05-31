use std::{
    collections::HashMap,
    fs::File,
    vec::Vec, io::Write,
};

use openssl::{
    pkey::Private,
    rsa::Rsa,
    x509::X509
};

use crate::keys::rsa::generate_rsa_key;
use crate::certificates::x509;

pub struct Pki {
    pub name: &'static str,
    authority: HashMap<String, (X509, Rsa<Private>)>,
    certs: HashMap<String, (X509, Rsa<Private>)>,
    serial: u32,
}

impl Pki {
    pub fn new() -> Pki {
        Pki {
            name: "newPki",
            authority: HashMap::new(),
            certs:HashMap::new(),
            serial: 0,
        }
    }

    pub fn add_authority(&self, length: u32, name: String) -> Result<&Self, &'static str> {
        let key: Rsa<Private> = generate_rsa_key(length);
        let private: Vec<u8> = key.private_key_to_pem().unwrap();
        let cert = x509::generate_rsa_authority(key, self.serial)?;

        let mut key_file = File::create(format!("{}.pem", name)).unwrap();
        let mut cert_file = File::create(format!("{}.crt", name)).unwrap();

        key_file.write_all(&private).unwrap();
        cert_file.write_all(&cert.to_text().unwrap()).unwrap();

        Ok(self)
    }

    pub fn get_authorities(&self) -> Vec<&String> {
        self.authority
            .iter()
            .fold(Vec::new(), |mut acc, (k, _)| {acc.push(k); acc })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_authorities() {
        assert_eq!(1, 1);
    }
}