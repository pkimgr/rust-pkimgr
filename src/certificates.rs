use openssl::{
    ec::EcKey,
    pkey::Private,
    rsa::Rsa,
    x509::X509Name,
};
use x509::CertEntries;

pub mod x509;
mod utils;

#[derive(Clone)]
pub enum PrivateKeyEnums {
    PrivateRsa(Rsa<Private>),
    Ecurve(EcKey<Private>),
}

pub struct CertArgs {
    pub authority_issuer: Box<Option<X509Name>>,
    pub authority_pkey: Option<PrivateKeyEnums>,
    pub key: PrivateKeyEnums,
    pub name: String,
    pub cert_entries: Box<CertEntries>
}
