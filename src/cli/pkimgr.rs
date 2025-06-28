use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    path::PathBuf,
};

use log::info;

use crate::{
    certificates::Certificate,
    configuration::Configuration,
    key::Key,
    pki::{Pki, PkiJSON}
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

    pub fn add_authority(self: &mut Self, pki_name: &String, auth_name: Option<&String>, cert_name: &String, key: Key) -> Result<&Self, String> {
        let pki = self.get_mut_pki_from_name(pki_name)?;

        pki.add_authority(cert_name, auth_name, key)
            .map_err(|err| format!("Failed to add authority: {}", err))?;

        Ok(self)
    }

    pub fn add_certificate(self: &mut Self, pki_name: &String, cert_name: &String, authority_name: &String, key: Key) -> Result<&Self, String> {
        let pki = self.get_mut_pki_from_name(pki_name)?;

        pki.add_certificate(
            cert_name,
            authority_name,
            key
        ).map_err(|err| format!("Failed to add RSA certificate: {}", err))?;

        Ok(self)
    }

    pub fn save(self: &Self) -> Result<&Self, String> {
        for (name, pki) in &self.pki {
            pki.save().map_err(|err| format!("Failed to save PKI {}: {}", name, err))?;
        }

        Ok(self)
    }

    pub fn parse_pki_file(self: &mut Self, pki_file: File) -> Result<&Self, String> {
        let json: PkiJSON = serde_json::from_reader(
            BufReader::new(pki_file)
        ).map_err(|err: serde_json::Error| format!("RORO {}", err))?;

        self.new_pki(&json.pki_name, None);

        // Add Root Authority
        let key = Key::new(
            json.root.keylen,
            json.root.curve
        ).map_err(|err| format!("Failed to create root key: {}", err))?;

        self.add_authority(&json.pki_name, None, &json.root.cname, key)?;

        for cert in json.root.subcerts {
            self.recurse_cert_manager(&json.pki_name, &json.root.cname, cert)
                .map_err(|err| format!("Error while creating certificate: {}", err))?;
        }

        info!("PKI {} created", json.pki_name);
        self.save().map_err(|err| format!("Failed to save PKI after parsing file: {}", err))?;

        Ok(self)
    }


    // Private
    fn get_mut_pki_from_name(self: &mut Self, pki_name: &String) -> Result<&mut Pki, String> {
        self.pki.get_mut(pki_name)
            .ok_or_else(|| format!("PKI {} not found", pki_name))
    }

    fn recurse_cert_manager(self: &mut Self, pki_name: &String, root: &String, cert: Certificate) -> Result<(), String> {
        let key = Key::new(
            cert.keylen,
            cert.curve
        ).map_err(|err| format!("Failed to create key for certificate {}: {}", &cert.cname, err))?;

        if cert.subcerts.len() == 0 {
            info!("Adding certificate {}", &cert.cname);
            self.add_certificate(
                pki_name,
                &cert.cname,
                root,
                key
            ).map_err(|err| format!("Failed to add certificate {}: {}", &cert.cname, err))?;
        } else {
            info!("Adding sub CA {} root ({})", &cert.cname, root);
            self.add_authority(
                pki_name,
                Some(root),
                &cert.cname,
                key
            ).map_err(|err| format!("Failed to add authority {}: {}", &cert.cname, err))?;


            for sub_cert in cert.subcerts {
                self.recurse_cert_manager(pki_name, &cert.cname, sub_cert)?;
            }
        }

        Ok(())
    }
}
