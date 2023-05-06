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
    pub name: String,
    authority: HashMap<String, (X509, Rsa<Private>)>,
    certs: HashMap<String, (X509, Rsa<Private>)>,
}

impl Pki {
    pub fn new() -> Pki {
        Pki {
            name: String::from("NewPki"),
            authority: HashMap::new(),
            certs:HashMap::new()
        }
    }

    pub fn add_certificate(&self, length: u32, authority: Option<X509>) -> Result<(), ()>{
        let key: Rsa<Private> = generate_rsa_key(length);
        let private_key: Vec<u8> = key.private_key_to_pem().unwrap();
        let cert: X509 = x509::generate_rsa_certificate(key, authority);
        let mut key_file = File::create("test.pem").unwrap();
        let mut cert_file = File::create("test.crt").unwrap();

        let t = cert.to_text().unwrap();
         
        key_file.write_all(&private_key).unwrap();
        cert_file.write_all(&t).unwrap();

        Ok(())
    }

    pub fn get_authorities(&self) -> Vec<&String> {
        let t: Vec<&String> = self.authority
            .iter()
            .fold(Vec::new(), |mut acc, (k, _)| {acc.push(k); acc });

        dbg!(t);

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_authorities() {
        assert_eq!(1, 1);
    }
}