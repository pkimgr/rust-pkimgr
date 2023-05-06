use openssl::{
    rsa::Rsa,
    pkey::Private
};

pub fn generate_rsa_key(length: u32) -> Rsa<Private> {
    Rsa::generate(length).unwrap()
}