use openssl::{
    x509::{
        X509, X509Builder,
        X509NameBuilder, X509Name
    },
    asn1::{Asn1Time, Asn1Integer}, bn::BigNum, error::ErrorStack
};

pub mod x509;

fn x509_name() -> Result<X509Name,  ErrorStack> {
    let mut x509_name: X509NameBuilder = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "uk")?;
    x509_name.append_entry_by_text("ST", "uk")?;
    x509_name.append_entry_by_text("O", "New organization")?;
    x509_name.append_entry_by_text("CN", "www.example.com")?;

    Ok(x509_name.build())
}

fn x509_builder(serial: u32)  -> Result<X509Builder, ErrorStack> {
    let mut x509_builder: X509Builder = X509::builder()?;

    x509_builder.set_not_before(
        &Asn1Time::days_from_now(0).unwrap()
    )?;
    x509_builder.set_not_after(
        &Asn1Time::days_from_now(365).unwrap()
    )?;

    x509_builder.set_serial_number(
        &Asn1Integer::from_bn(
            &BigNum::from_u32(serial).unwrap()
        ).unwrap()
    )?;

    Ok(x509_builder)
}