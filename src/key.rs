use log::info;
use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::Rsa
};

#[derive(Clone)]
pub enum KeyType {
    Rsa(Rsa<Private>),
    Ec(EcKey<Private>),
}
const DEFAULT_KEYLEN: u32 = 4096;
const DEFAULT_CURVE: Nid = Nid::SECP256K1;

impl KeyType {
    pub fn new(length: Option<u32>, curve: Option<String>) -> Result<KeyType, ErrorStack> {
        let new_key = match (length, curve) {
            (Some(len), _) => KeyType::Rsa(Rsa::generate(len)?),
            (_, Some(curve)) => {
                let group = EcGroup::from_curve_name(
                    string_to_curve(curve)?
                )?;

                KeyType::Ec(EcKey::generate(&group)?)
            },
            _ => KeyType::Rsa(Rsa::generate(DEFAULT_KEYLEN)?)
        };

        Ok(new_key)
    }

    pub fn to_private_pkey(&self) -> Result<PKey<Private>, ErrorStack> {
        match self {
            KeyType::Rsa(key) => PKey::from_rsa(key.clone()),
            KeyType::Ec(key) => PKey::from_ec_key(key.clone()),
        }
    }

    pub fn to_public_pkey(&self) -> Result<PKey<Public>, ErrorStack> {
        let pem = self.to_private_pkey()?.public_key_to_pem()?;

        Ok(PKey::public_key_from_pem(&pem)?)
    }

    pub fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        self.to_private_pkey()?.private_key_to_pem_pkcs8()
    }
}

fn string_to_curve(curve: String) -> Result<Nid, ErrorStack> {
    match curve.to_lowercase().as_str() {
        "secp256k1" => Ok(Nid::SECP256K1),
        "secp384r1" => Ok(Nid::SECP384R1),
        "secp521r1" => Ok(Nid::SECP521R1),
        _ => {
            info!("Unsupported curve: {}. Defaulting to SECP256K1", curve);
            Ok(DEFAULT_CURVE)
        }
    }
}