use openssl::{
    ec::EcKey,
    error::ErrorStack,
    pkey::{Private, PKey},
    rsa::Rsa,
    x509::X509NameRef,
};

use crate::configuration::Configuration;

pub mod x509;

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

#[derive(Clone, Copy)]
pub struct CertBuilders<'a> {
    conf: Configuration<'a>
}

pub fn get_pkey(key: PrivateKeyEnums) -> Result<PKey<Private>, ErrorStack> {
    let key: PKey<Private> = match key {
        PrivateKeyEnums::PrivateRsa(key) => PKey::from_rsa(key)?,
        PrivateKeyEnums::Ecurve(key) => PKey::from_ec_key(key)?,
    };

    Ok(key)
}