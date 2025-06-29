// Todo: Add CLI functionality for the pkimgr module
// Todo: pkimgr submodule should not be pubic
use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
    io::{BufReader, Write},
    path::{Path, PathBuf},
};

use log::{info, debug, error};

use crate::{
    certificates::Certificate,
    Configuration,
    error::ManagerError,
    key::Key,
    pki::{Pki, PkiJSON},
    CERTS_DIR,
    PEM_DIR
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


    pub fn create_from_file(self: &mut Self, pki_file: File) -> Result<&Self, ManagerError> {
        let json: PkiJSON = serde_json::from_reader(
            BufReader::new(pki_file)
        )?;

        self.new_pki(&json.pki_name, None);

        // Add Root Authority
        let key = Key::new(json.root.keylen, json.root.curve)?;

        self.create_authority(&json.pki_name, None, &json.root.cname, key)?;

        for cert in json.root.subcerts {
            match self.add_recursive_cert(&json.pki_name, &json.root.cname, cert) {
                Ok(_) => info!("PKI {} successfully created", &json.pki_name),
                Err(err) => error!("Cannot create PKI {}: {}", &json.pki_name, err)
            }
        }

        debug!("PKI {} created, save it", json.pki_name);
        self.save()
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
            pki_name,
            configuration
        );

        self.pki.insert(pki_name.to_owned(), pki);

        self
    }


    pub fn create_authority(
        self: &mut Self,
        pki_name: &String,
        auth_name: Option<&String>,
        cert_name: &String,
        key: Key
    ) -> Result<&Self, ManagerError> {
        let pki = self.pki_from_name_as_mut(pki_name)?;

        pki.add_authority(cert_name, auth_name, key)?;

        Ok(self)
    }


    pub fn create_certificate(
        self: &mut Self,
        pki_name: &String,
        cert_name: &String,
        auth_name: &String,
        key: Key
    ) -> Result<&Self, ManagerError> {
        let pki = self.pki_from_name_as_mut(pki_name)?;

        pki.add_certificate(cert_name, auth_name, key)?;

        Ok(self)
    }


    pub fn save(self: &Self) -> Result<&Self, ManagerError> {
        for (_, pki) in self.pki.clone() {
            let path = Path::join(&self.base_path, pki.name);

            if !path.exists() {
                create_dir_all(Path::join(&path, CERTS_DIR))?;
                create_dir_all(Path::join(&path, PEM_DIR))?;
            }


            for (name, (cert, key)) in pki.authorities.clone() {
                write_cert_file(&path, &name, cert.to_pem()?, key.to_pem()?)?;
            }

            for (name, (cert, key)) in pki.certs.clone() {
                write_cert_file(&path, &name, cert.to_pem()?, key.to_pem()?)?;
            }

            File::create(Path::join(&path, "metadata.json"))?
                .write_all(format!("{}", pki.json).as_bytes())?;
        }

        Ok(self)
    }


    // Private
    fn pki_from_name_as_mut(self: &mut Self, pki_name: &String) -> Result<&mut Pki, ManagerError> {
        self.pki.get_mut(pki_name)
            .ok_or_else(|| ManagerError::NotFound(format!("Cannot find {}", &pki_name)))
    }


    fn add_recursive_cert(self: &mut Self, pki_name: &String, root: &String, cert: Certificate) -> Result<(), ManagerError> {
        let key = Key::new(cert.keylen, cert.curve)?;

        if cert.subcerts.len() == 0 {
            debug!("Adding certificate {}", &cert.cname);
            self.create_certificate(pki_name, &cert.cname, root, key)?;
        } else {
            debug!("Adding sub CA {} root ({})", &cert.cname, root);
            self.create_authority(pki_name, Some(root), &cert.cname, key)?;

            for sub_cert in cert.subcerts {
                self.add_recursive_cert(pki_name, &cert.cname, sub_cert)?;
            }
        }

        Ok(())
    }
}


fn write_cert_file(path: &Path, name: &String, cert_pem: Vec<u8>, private_key: Vec<u8>) -> Result<(), ManagerError> {
    File::create(format!(
        "{}/{}.pem", Path::join(path, PEM_DIR).to_str().unwrap(),
        &name
    ))?.write_all(&private_key)?;

    File::create(format!(
        "{}/{}.crt", Path::join(path, CERTS_DIR).to_str().unwrap(),
        &name,
    ))?.write_all(&cert_pem)?;


    Ok(())
}