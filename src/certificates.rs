use openssl::x509::X509Name;
use serde::{Deserialize, Serialize};

use crate::key::Key;

pub mod x509;

#[derive(Serialize, Deserialize, Clone)]
pub struct X509CertEntries {
    pub country: Box<str>,
    pub state: Box<str>,
    pub organization: Box<str>,
    pub validity: u32
}

pub struct CertArgs {
    pub authority_issuer: Option<X509Name>,
    pub authority_pkey: Option<Key>,
    pub key: Key,
    pub name: String,
    pub cert_entries: X509CertEntries
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Certificate {
    pub cname: String,
    pub subcerts: Vec<Certificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keylen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}
