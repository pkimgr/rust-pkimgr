use openssl::x509::X509Name;
use serde::{Deserialize, Serialize};

use crate::key::KeyType;

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
    pub authority_pkey: Option<KeyType>,
    pub key: KeyType,
    pub name: String,
    pub cert_entries: X509CertEntries
}
