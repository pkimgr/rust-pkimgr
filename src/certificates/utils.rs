use openssl::{
    error::ErrorStack,
    pkey::{Private, PKey},
};

use super::PrivateKeyEnums;

pub fn get_pkey(key: PrivateKeyEnums) -> Result<PKey<Private>, ErrorStack> {
    let key: PKey<Private> = match key {
        PrivateKeyEnums::PrivateRsa(key) => PKey::from_rsa(key)?,
        PrivateKeyEnums::Ecurve(key) => PKey::from_ec_key(key)?,
    };

    Ok(key)
}