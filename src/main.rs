// Here someday, the divine CLI will exist
use pkimgr::pki::Pki;
pub fn main() {
    let pki: Pki = Pki::new();

    pki.add_certificate(3072, None).unwrap();
}