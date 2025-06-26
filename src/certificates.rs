use openssl::{

    pkey::{PKey, Private}, x509::X509Name
};
use serde::{Deserialize, Serialize};

pub mod x509;
use crate::key::Key;

#[derive(Serialize, Deserialize, Clone)]
pub struct X509CertEntries {
    pub country: Box<str>,
    pub state: Box<str>,
    pub organization: Box<str>,
    pub validity: u32
}

pub struct CertArgs<'a> {
    pub authority_issuer: Option<X509Name>,
    pub authority_pkey: Option<PKey<Private>>,
    pub key: &'a dyn Key,
    pub name: String,
    pub cert_entries: X509CertEntries
}
