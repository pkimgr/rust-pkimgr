use std::path::Path;

// Here someday, the divine CLI will exist
use pkimgr::pki::Pki;

pub fn main() {
    let path: &Path = Path::new("pki/TEST");
    let pki: Pki = Pki::new(path).unwrap();

    println!("Generate new authority");

    pki.add_authority(3072, String::from("authority")).unwrap();
}