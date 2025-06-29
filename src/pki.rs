use core::fmt;
use std::collections::HashMap;

use log::error;
use openssl::x509::X509;
use serde::{Serialize, Deserialize};
use serde_json;

use crate::{
    certificates::{
        x509::{create_x509_leaf, create_x509_node, x509_to_certificate},
        CertArgs,
        Certificate
    }, Configuration, error::PKIError, key::Key
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PkiJSON {
    pub pki_name: String,
    pub root: Certificate
}

impl fmt::Display for PkiJSON {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string_pretty(&self).unwrap_or_else(|err| {
                error!("Cannot write metadata: {}", err);
                err.to_string()
            })
        )

    }
}

#[derive(Clone)]
pub struct Pki {
    pub name: String,
    pub authorities: HashMap<String, (X509, Key)>,
    pub certs: HashMap<String, (X509, Key)>,
    // path: PathBuf,
    pub json: PkiJSON,
    configuration: Configuration
}

impl Pki {
    pub fn new(pki_name: &String, configuration: Configuration) -> Pki {
        Pki {
            name: pki_name.into(),
            authorities: HashMap::new(),
            certs: HashMap::new(),
            json: PkiJSON {
                pki_name: pki_name.into(),
                root: Certificate::default()
            },
            configuration
        }
    }


    pub fn load(json: PkiJSON, configuration: Configuration) -> Pki {
        // TODO Load existing PKI here
        // must be removed
        Pki::new(&json.pki_name, configuration)
    }


    pub fn get_configuration(self: &Self) -> Configuration {
        self.configuration.clone()
    }


    pub fn add_authority(self: &mut Self, name: &String, auth_name: Option<&String>, key: Key) -> Result<&Self, PKIError> {
        let (authority_issuer, authority_pkey) = match auth_name {
            Some(name) => {
                let (cert, key) = self.find_authority(name)?;

                (Some(cert.subject_name().to_owned()?), Some(key.to_owned()))
            },
            None => (None, None)
        };

        let cert = create_x509_node(
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


    pub fn add_certificate(self: &mut Self, name: &String, auth_name: &String, key: Key) -> Result<&Self, PKIError> {
        let (issuer_cert, issuer_key) = self.find_authority(auth_name)?;

        let cert = create_x509_leaf(
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


    // Privates
    fn find_authority(self: &mut Self, name: &String) -> Result<&(X509, Key), PKIError> {
        self.authorities.get(name)
            .ok_or_else(|| PKIError::NotFound(format!("{} not found on {}", name, self.name)))
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