use openssl::{
    ec::EcKey,
    pkey::Private,
    rsa::Rsa,
    x509::X509NameRef,
};

use super::configuration::Configuration;

pub mod x509;
mod utils;

#[derive(Clone)]
pub enum PrivateKeyEnums {
    PrivateRsa(Rsa<Private>),
    Ecurve(EcKey<Private>),
}

pub struct CertArgs<'a> {
    pub authority_issuer: Option<&'a X509NameRef>,
    pub authority_pkey: Option<PrivateKeyEnums>,
    pub key: PrivateKeyEnums,
    pub name: String,
}

#[derive(Clone)]
pub struct CertsBuilder {
    conf: Box<Configuration>
}
