use openssl::{
    asn1::{ Asn1Integer, Asn1Time },
    bn::{ BigNum, MsbOption },
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{ PKey, Private },
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Builder,
        X509Name,
        X509NameBuilder,
        X509NameRef,
        X509Req,
        X509ReqBuilder,
        X509
    }
};
use serde::{Deserialize, Serialize};

use super::{
    CertArgs,
    utils::get_pkey
};

#[derive(Serialize, Deserialize, Clone)]
pub struct CertEntries {
    pub country: Box<str>,
    pub state: Box<str>,
    pub organization: Box<str>,
    pub validity: u32
}


pub fn generate_authority(args: CertArgs) -> Result<X509, ErrorStack> {
    // name
    let mut name_builder: X509NameBuilder = _get_name_builder(&args.cert_entries)?;
    name_builder.append_entry_by_text("CN", &args.name)?;

    let name: X509Name = name_builder.build();
    let pkey: PKey<Private> = get_pkey(args.key)?;

    // builder
    let mut cert_builder: X509Builder  =  _get_x509_builder(&args.cert_entries, &pkey)?;
    cert_builder.set_issuer_name(&name)?;
    cert_builder.set_subject_name(&name)?;

    // constraints on extensions
    let mut bc: BasicConstraints = BasicConstraints::new();
    cert_builder.append_extension(
        bc.critical().ca().build().unwrap()
    )?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?
    )?;

    cert_builder.sign(&pkey, MessageDigest::sha3_256())?;

    Ok(cert_builder.build())
}

pub fn generate_certificate(args: CertArgs) -> Result<X509, ErrorStack> {
    // Name builder
    let mut name_builder = _get_name_builder(&args.cert_entries)?;
    name_builder.append_entry_by_text("CN", &args.name)?;

    // Create CSR
    let key: PKey<Private> = get_pkey(args.key)?;
    let req: X509Req = _get_x509_req(&key, name_builder)?;

    // Authority key
    let cert_authority: &X509NameRef = &args.authority_issuer.ok_or("Cannot find Authority").unwrap();
    let ca_pkey: PKey<Private> = get_pkey(args.authority_pkey.unwrap())?;

    // cert
    let mut cert_builder: X509Builder = _get_x509_builder(&args.cert_entries, &key)?;
    cert_builder.set_subject_name(&req.subject_name())?;
    cert_builder.set_issuer_name(cert_authority)?;


    cert_builder.sign(&ca_pkey, MessageDigest::sha3_256())?;

    Ok(cert_builder.build())
}

fn _get_name_builder(cert_conf: &CertEntries) -> Result<X509NameBuilder, ErrorStack> {
    let mut name_builder: X509NameBuilder = X509NameBuilder::new()?;

    name_builder.append_entry_by_text("C", &cert_conf.country)?;
    name_builder.append_entry_by_text("ST",  &cert_conf.state)?;
    name_builder.append_entry_by_text("O", &cert_conf.organization)?;

    Ok(name_builder)
}

fn _get_x509_builder(cert_conf: &CertEntries, pkey: &PKey<Private>) -> Result<X509Builder, ErrorStack> {
    let mut x509_builder : X509Builder= X509::builder()?;

    x509_builder.set_version(2)?;

    x509_builder.set_not_before(
        &Asn1Time::days_from_now(0).unwrap()
    )?;
    x509_builder.set_not_after(
        &Asn1Time::days_from_now(cert_conf.validity).unwrap()
    )?;

    let serial_number: Asn1Integer= {
        let mut serial: BigNum = BigNum::new()?;
        serial.rand(256, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    x509_builder.set_serial_number(&serial_number)?;

    x509_builder.set_pubkey(&pkey)?;

    Ok(x509_builder)
}

fn _get_x509_req(pkey: &PKey<Private>, name_builder: X509NameBuilder) -> Result<X509Req, ErrorStack> {
    let mut req_builder: X509ReqBuilder = X509ReqBuilder::new()?;

    req_builder.set_pubkey(&pkey)?;
    req_builder.set_subject_name(&name_builder.build())?;
    req_builder.sign(&pkey, MessageDigest::sha3_256())?;

    Ok(req_builder.build())
}