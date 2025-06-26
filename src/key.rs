use openssl::{
    ec::EcKey,
    error::ErrorStack,
    pkey::{PKey, Private, Public},
    rsa::Rsa
};

pub trait Key {
    fn get_private_key(&self) -> Result<PKey<Private>, ErrorStack>;
    fn get_public_key(&self) -> Result<PKey<Public>, ErrorStack>;
    fn to_pem(&self) -> Result<Vec<u8>, ErrorStack>;
}

impl Key for Rsa<Private>  {
    fn get_private_key(&self) -> Result<PKey<Private>, ErrorStack> {
        PKey::from_rsa(self.clone())
    }

    fn get_public_key(&self) -> Result<PKey<Public>, ErrorStack> {
        let public = self.public_key_to_pem()?;

        let key = Rsa::public_key_from_pem(&public).expect("Failed to get RSA public key from PEM");
        PKey::from_rsa(key.clone())
    }

    fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        self.private_key_to_pem()
    }

}

impl Key for EcKey<Private> {
    fn get_private_key(&self) -> Result<PKey<Private>, ErrorStack> {
        PKey::from_ec_key(self.clone())
    }

    fn get_public_key(&self) -> Result<PKey<Public>, ErrorStack> {
        let public = self.public_key_to_pem()?;

        let key = EcKey::public_key_from_pem(&public).expect("Failed to get EC public key from PEM");
        PKey::from_ec_key(key.clone())
    }

    fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        self.private_key_to_pem()
    }
}
