use openssl::{
    asn1::{ Asn1Integer, Asn1Time },
    bn::{ BigNum, MsbOption },
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{ PKey, Private },
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509NameBuilder, X509Builder,
        X509, X509Name,
        X509NameRef, X509Req, X509ReqBuilder
    },
};

use crate::Configuration;
use crate::certificates::{ CertArgs, CertBuilders, get_pkey };

impl <'a> CertBuilders<'a> {
    pub fn new(conf: Configuration) -> CertBuilders {
        CertBuilders { conf }
    }

    pub fn generate_authority(&self, args: CertArgs) -> Result<X509, ErrorStack> {
        // name
        let mut name_builder: X509NameBuilder = self.get_name_builder()?;
        name_builder.append_entry_by_text("CN", &args.name)?;

        let name: X509Name = name_builder.build();
        let pkey: PKey<Private> = get_pkey(args.key)?;

        // builder
        let mut cert_builder: X509Builder  =  self.get_x509_builder(&pkey)?;
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

    pub fn generate_certificate(&self, args: CertArgs) -> Result<X509, ErrorStack> {
        // name builder
        let cert_authority: &X509NameRef = args.authority_issuer.ok_or("Cannot find Authority").unwrap();

        let key: PKey<Private> = get_pkey(args.key)?;
        let req: X509Req = self.get_x509_req(&key,&args.name)?;

        // cert_builder
        let mut cert_builder: X509Builder = self.get_x509_builder(
            &key
        )?;
        cert_builder.set_subject_name(&req.subject_name())?;
        cert_builder.set_issuer_name(cert_authority)?;

        let ca_pkey: PKey<Private> = get_pkey(args.authority_pkey.unwrap())?;
        cert_builder.sign(&ca_pkey, MessageDigest::sha3_256())?;

        Ok(cert_builder.build())
    }

    fn get_name_builder(self) -> Result<X509NameBuilder, ErrorStack> {
        let mut name_builder: X509NameBuilder = X509NameBuilder::new()?;

        name_builder.append_entry_by_text("C", self.conf.country)?;
        name_builder.append_entry_by_text("ST", self.conf.state)?;
        name_builder.append_entry_by_text("O", self.conf.organization)?;

        Ok(name_builder)
    }

    fn get_x509_builder(self, pkey: &PKey<Private>) -> Result<X509Builder, ErrorStack> {
        let mut x509_builder : X509Builder= X509::builder()?;

        x509_builder.set_version(2)?;

        x509_builder.set_not_before(
            &Asn1Time::days_from_now(0).unwrap()
        )?;
        x509_builder.set_not_after(
            &Asn1Time::days_from_now(self.conf.validity).unwrap()
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

    fn get_x509_req(self, pkey: &PKey<Private>, cname: &String) -> Result<X509Req, ErrorStack> {
        let mut req_builder: X509ReqBuilder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(&pkey)?;

        let mut x509_name: X509NameBuilder = self.get_name_builder()?;
        x509_name.append_entry_by_text("CN", cname)?;
        req_builder.set_subject_name(&x509_name.build())?;

        req_builder.sign(&pkey, MessageDigest::sha3_256())?;

        Ok(req_builder.build())
    }
}
