use core::fmt;
use std::str::FromStr;

use log::info;
use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::Rsa
};

use serde::{Deserialize, Serialize};


const DEFAULT_KEYLEN: u32 = 4096;


#[derive(Clone)]
pub enum Key {
    Rsa(Rsa<Private>),
    Ec(EcKey<Private>),
}


impl Key {
    pub fn new(length: Option<u32>, curve: Option<String>) -> Result<Key, ErrorStack> {
        let new_key = match (length, curve) {
            (Some(len), _) => Key::Rsa(Rsa::generate(len)?),
            (_, Some(curve)) => {
                let group = EcGroup::from_curve_name(
                    curve.parse::<Curve>()
                        .unwrap_or(Curve::Secp256k1)
                        .into()
                )?;

                Key::Ec(EcKey::generate(&group)?)
            },
            _ => Key::Rsa(Rsa::generate(DEFAULT_KEYLEN)?)
        };

        Ok(new_key)
    }


    pub fn to_private_pkey(&self) -> Result<PKey<Private>, ErrorStack> {
        match self {
            Key::Rsa(key) => PKey::from_rsa(key.clone()),
            Key::Ec(key) => PKey::from_ec_key(key.clone()),
        }
    }


    pub fn to_public_pkey(&self) -> Result<PKey<Public>, ErrorStack> {
        let pem = self.to_private_pkey()?.public_key_to_pem()?;

        Ok(PKey::public_key_from_pem(&pem)?)
    }


    pub fn rsa_len(&self) -> Option<u32> {
        match self {
            Key::Rsa(key) => Some(key.size() as u32 * 8),
            Key::Ec(_) => None,
        }
    }


    pub fn curve(&self) -> Option<String> {
        match self {
            Key::Rsa(_) => None,
            Key::Ec(key) => {
                let nid = key.group().curve_name()?;

                Some(format!("{}",Curve::try_from(nid).unwrap()))
            }
        }
    }


    pub fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        self.to_private_pkey()?.private_key_to_pem_pkcs8()
    }
}

// EC management type
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Curve {
    Secp256k1,
    Secp384r1,
    Secp521r1,
}


impl FromStr for Curve {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "secp256k1" => Ok(Curve::Secp256k1),
            "secp384r1" => Ok(Curve::Secp384r1),
            "secp521r1" => Ok(Curve::Secp521r1),
            _ => {
                info!("Unknown curve: {}. Defaulting to {}", s, Curve::Secp256k1);

                Ok(Curve::Secp256k1)
            }
        }
    }
}


impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Curve::Secp256k1 => write!(f, "secp256k1"),
            Curve::Secp384r1 => write!(f, "secp384r1"),
            Curve::Secp521r1 => write!(f, "secp521r1"),
        }
    }
}


impl From<Curve> for Nid {
    fn from(curve: Curve) -> Self {
        match curve {
            Curve::Secp256k1 => Nid::SECP256K1,
            Curve::Secp384r1 => Nid::SECP384R1,
            Curve::Secp521r1 => Nid::SECP521R1,
        }
    }
}


impl TryFrom<Nid> for Curve {
    type Error = String;

    fn try_from(nid: Nid) -> Result<Self, Self::Error> {
        match nid {
            Nid::SECP256K1 => Ok(Curve::Secp256k1),
            Nid::SECP384R1 => Ok(Curve::Secp384r1),
            Nid::SECP521R1 => Ok(Curve::Secp521r1),
            _ => Err(format!("Unsupported curve: {:?}", nid)),
        }
    }
}