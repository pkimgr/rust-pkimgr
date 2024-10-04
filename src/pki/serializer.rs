use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedCertificate {
    pub cname: String,
    pub subcerts: Vec<SerializedCertificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keylen: Option<u32>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Serializer {
    pub pki_name: String,
    pub root: SerializedCertificate
}

impl Serializer {
    pub fn new(pki_name: String) -> Serializer {
        Serializer {
            pki_name,
            root: SerializedCertificate { cname: "".to_string(), subcerts: Vec::from([]), keylen: None }
        }
    }

    pub fn add_certificate(self: &mut Self, cname: &String, auth_cname: &String, key_len: u32) -> bool {
        if self.root.cname.is_empty() && cname.as_str().eq(auth_cname.as_str()) {
            self.root.cname = cname.to_owned();
            self.root.keylen = Some(key_len);
            return true;
        }
        recurse_add(&mut self.root, cname, auth_cname, key_len)
    }
}

fn recurse_add(cert: &mut SerializedCertificate, cname: &String, auth_cname: &String, key_len: u32) -> bool {
    if cert.cname.as_str().eq(auth_cname.as_str()) {
        cert.subcerts.push(SerializedCertificate {
            cname: cname.to_owned(),
            subcerts: Vec::from([]),
            keylen: Some(key_len)
        });

        return true
    }

    for crt in cert.subcerts.as_mut_slice() {
        return recurse_add(crt, cname, auth_cname, key_len);
    }

    false
}
