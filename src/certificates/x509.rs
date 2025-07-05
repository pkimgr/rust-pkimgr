use openssl::{
    asn1::{ Asn1Integer, Asn1Time },
    bn::{ BigNum, MsbOption },
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{ PKey, Private, Public },
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Builder,
        X509Name,
        X509NameBuilder,
        X509Req,
        X509ReqBuilder,
        X509
    }
};

use crate::{
    certificates::{CertArgs, Certificate, X509Info},
    key::Key
};


pub fn create_x509_node(args: CertArgs) -> Result<X509, ErrorStack> {
    // name
    let mut name_builder: X509NameBuilder = _get_name_builder(&args.cert_entries)?;
    name_builder.append_entry_by_text("CN", &args.name)?;

    let name: X509Name = name_builder.build();
    let public_key: PKey<Public> = args.key.to_public_pkey()?;

    // builder
    let mut cert_builder: X509Builder  =  _get_x509_builder(&args.cert_entries, &public_key)?;

    if args.authority_issuer.is_none() {
        cert_builder.set_issuer_name(&name)?;
    } else {
       let cert_authority: &X509Name = &args.authority_issuer.ok_or(ErrorStack::get())?;

       cert_builder.set_issuer_name(cert_authority)?;
    }

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

    let private_key: PKey<Private> = match args.authority_pkey {
        Some(pkey) => pkey.to_private_pkey()?,
        None => args.key.to_private_pkey()?
    };
    cert_builder.sign(&private_key, MessageDigest::sha3_256())?;

    Ok(cert_builder.build())
}


pub fn create_x509_leaf(args: CertArgs) -> Result<X509, ErrorStack> {
    // Name builder
    let mut name_builder = _get_name_builder(&args.cert_entries)?;
    name_builder.append_entry_by_text("CN", &args.name)?;

    // Create CSR
    let key: PKey<Private> = args.key.to_private_pkey()?;
    let req: X509Req = _get_x509_req(&key, name_builder)?;

    // Authority key
    let cert_authority: &X509Name = &args.authority_issuer.ok_or(ErrorStack::get())?;
    let ca_pkey: PKey<Private> = args.authority_pkey
        .ok_or(ErrorStack::get())
        .and_then(|pkey| pkey.to_private_pkey())?
    ;

    // cert
    let public_key: PKey<Public> = args.key.to_public_pkey()?;
    let mut cert_builder: X509Builder = _get_x509_builder(&args.cert_entries, &public_key)?;
    cert_builder.set_subject_name(&req.subject_name())?;
    cert_builder.set_issuer_name(cert_authority)?;

    cert_builder.sign(&ca_pkey, MessageDigest::sha3_256())?;

    Ok(cert_builder.build())
}


pub fn x509_to_certificate(cert: &X509, key: &Key) -> Certificate {
    Certificate {
        cname: cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .map(|entry| entry.data().as_utf8().unwrap().to_string())
            .unwrap_or_default(),
        subcerts: vec![],
        keylen: key.rsa_len(),
        curve: key.curve()
    }
}


// Private
fn _get_name_builder(cert_conf: &X509Info) -> Result<X509NameBuilder, ErrorStack> {
    let mut name_builder: X509NameBuilder = X509NameBuilder::new()?;

    name_builder.append_entry_by_text("C", &cert_conf.country)?;
    name_builder.append_entry_by_text("ST",  &cert_conf.state)?;
    name_builder.append_entry_by_text("O", &cert_conf.organization)?;

    Ok(name_builder)
}


fn _get_x509_builder(cert_conf: &X509Info, key: &PKey<Public>) -> Result<X509Builder, ErrorStack> {
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

    x509_builder.set_pubkey(&key)?;

    Ok(x509_builder)
}


fn _get_x509_req(pkey: &PKey<Private>, name_builder: X509NameBuilder) -> Result<X509Req, ErrorStack> {
    let mut req_builder: X509ReqBuilder = X509ReqBuilder::new()?;

    req_builder.set_pubkey(&pkey)?;
    req_builder.set_subject_name(&name_builder.build())?;
    req_builder.sign(&pkey, MessageDigest::sha3_256())?;

    Ok(req_builder.build())
}