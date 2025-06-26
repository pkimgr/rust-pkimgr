use std::{
    collections::HashMap, fs::File, io::BufReader, path::PathBuf
};

use openssl::{ec::{EcKey, EcGroup}, nid::Nid, rsa::Rsa};

use crate::{
    configuration::Configuration, key::Key, pki::Pki, serializer::pki::PkiSerializer, DEFAULT_KEYLEN
};

#[derive(Clone)]
pub struct Pkimgr {
    default_conf: Configuration,
    base_path: PathBuf,
    pki: HashMap<String, Pki>,
}

impl Pkimgr {
    pub fn new(configuration: Configuration, base_path: PathBuf) ->  Pkimgr {
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

    pub fn new_pki(self: &mut Self, pki_name: &String, config: Option<Configuration>) -> &Self  {
        let configuration = match config {
            None => self.default_conf.clone(),
            Some(c) => c
        };

        let pki = Pki::new(
            self.base_path.join(pki_name).into(),
            configuration
        ).expect("Cannot create new pki");

        self.pki.insert(pki_name.to_owned(), pki);

        self
    }

    pub fn add_authnority(self: &mut Self, pki_name: &String, cert_name: &String, key: &dyn Key) -> Result<&Self, String> {
        let pki = self.pki.get_mut(pki_name)
            .ok_or_else(|| format!("PKI {} not found", pki_name))?;

        pki.add_authnority(cert_name, key)
            .map_err(|err| format!("Failed to add authority: {}", err))?;

        Ok(self)
    }

    pub fn add_certificate(self: &mut Self, pki_name: &String, cert_name: &String, authority_name: &String, key: &dyn Key) -> Result<&Self, String> {
        let pki = self.pki.get_mut(pki_name)
            .ok_or_else(|| format!("PKI {} not found", pki_name))?;


        pki.add_certificate(
            cert_name,
            authority_name,
            key
        ).map_err(|err| format!("Failed to add RSA certificate: {}", err))?;

        Ok(self)
    }

    pub fn parse_pki_file(self: &mut Self, pki_file: File) -> Result<&Self, String> {
        let pki_serialized: PkiSerializer = serde_json::from_reader(
            BufReader::new(pki_file)
        ).map_err(|err| format!("RORO {}", err))?;

        self.new_pki(&pki_serialized.pki_name, None);

        // Add Root Authority
        let key = Rsa::generate(
            pki_serialized.root.keylen.unwrap_or(DEFAULT_KEYLEN)
        ).expect("Failed to generate RSA key");

        self.add_authnority(&pki_serialized.pki_name, &pki_serialized.root.cname, &key)?;

        for cert in pki_serialized.root.subcerts {
            if cert.subcerts.len() == 0 {
                let key: Box<dyn Key> = match (cert.keylen, cert.curve) {
                    (Some(len), None) => Box::new(Rsa::generate(len).expect("Failed to generate RSA key")),
                    (None, Some(_)) => {
                        let group = EcGroup::from_curve_name(Nid::SECP256K1).expect("TODO BETTer");
                        Box::new(
                            EcKey::generate(&group)
                                .map_err(|err| format!("Failed to generate EC key: {}", err))?
                        )
                    }
                    _ => Box::new(Rsa::generate(DEFAULT_KEYLEN).expect("Failed to generate RSA key"))
                };

                self.add_certificate(
                    &pki_serialized.pki_name,
                    &cert.cname,
                    &pki_serialized.root.cname,
                    key.as_ref()
                ).map_err(|err| format!("Failed to add certificate: {}", err))?;
            }
        }

        Ok(self)
    }
}