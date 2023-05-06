use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509, X509Builder, X509NameBuilder}, asn1::{ Asn1Integer, Asn1Time}, bn::BigNum,
};

pub fn generate_rsa_certificate(public_key: Rsa<Private>, authority: Option<X509>) -> X509 {
    let mut x509_builder: X509Builder = X509::builder().unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "uk").unwrap();
    x509_name.append_entry_by_text("ST", "uk").unwrap();
    x509_name.append_entry_by_text("O", "New organization").unwrap();
    x509_name.append_entry_by_text("CN", "www.example.com").unwrap();
    let x509_name = x509_name.build();

    match authority {
        Some(x) => {dbg!(x); ()},
        _ => {println!("coucou"); x509_builder.set_issuer_name(&x509_name).unwrap()}
    };
    x509_builder.set_subject_name(&x509_name).unwrap(); 

    x509_builder.set_not_before(
        &Asn1Time::days_from_now(0).unwrap()
    ).unwrap();
    
    x509_builder.set_not_after(
        &Asn1Time::days_from_now(365).unwrap()
    ).unwrap();
    
    x509_builder.set_pubkey(
        &PKey::from_rsa(public_key).unwrap()
    ).unwrap();
   
    x509_builder.set_serial_number(
        &Asn1Integer::from_bn(
            &BigNum::from_u32(1256789).unwrap()
        ).unwrap()
    ).unwrap();
    
    x509_builder.build() 
}