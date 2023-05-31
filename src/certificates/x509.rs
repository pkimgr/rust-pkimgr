use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509, X509Builder, extension::BasicConstraints},
    asn1::Asn1Integer,
    bn::BigNum,
};

use crate::certificates::{x509_name, x509_builder};

pub fn generate_rsa_authority(public_key: Rsa<Private>, serial: u32) -> Result<X509, &'static str> {
    // Name
    let x509name = match x509_name() {
        Ok(name ) => name,
        Err(error) => {
            eprintln!("Cannot get name {}", error);
            return Err("Cannot get name");
        }
    };
    // builder
    let mut builder: X509Builder = match x509_builder(serial) {
        Ok(cert) => cert,
        Err(error) => {
            eprintln!("Error {}", error);
            return Err("Cannot create certificate");
        }
    };
    // Set specific fields
    builder.set_subject_name(&x509name).unwrap();
    builder.set_pubkey(
        &PKey::from_rsa(public_key).unwrap()
    ).unwrap();
    builder.set_serial_number(
        &Asn1Integer::from_bn(
            &BigNum::from_u32(serial).unwrap()
        ).unwrap()
    ).unwrap();

    let mut bc = BasicConstraints::new();
    let ca = bc.ca();
    builder.append_extension(ca.build().unwrap()).unwrap();

    Ok(builder.build())
}