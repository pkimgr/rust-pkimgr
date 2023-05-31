// Here someday, the divine CLI will exist
use pkimgr::pki::Pki;
pub fn main() {
    let pki: Pki = Pki::new();

    println!("Generate new authority");

    pki.add_authority(3072, String::from("authority")).unwrap();
}