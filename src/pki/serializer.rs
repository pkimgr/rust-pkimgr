use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SerializedCertificate {
    cname: String,
    subcerts: Vec<SerializedCertificate>
}

#[derive(Serialize, Deserialize)]
pub struct SerializedPki {
    root: SerializedCertificate
}

impl SerializedPki {
    pub fn new() -> SerializedPki {
        SerializedPki {
            root: SerializedCertificate { cname: "".to_string(), subcerts: Vec::from([]) }
        }
    }

    pub fn add_certificate(self: &mut Self, cname: &String, auth_cname: &String) -> bool {
        if self.root.cname.is_empty() && cname.as_str().eq(auth_cname.as_str()) {
            self.root.cname = cname.to_owned();
            return true;
        }
        recurse_add(&mut self.root, cname, auth_cname)
    }
}

fn recurse_add(cert: &mut SerializedCertificate, cname: &String, auth_cname: &String) -> bool {
    if cert.cname.as_str().eq(auth_cname.as_str()) {
        cert.subcerts.push(SerializedCertificate { cname: cname.to_owned(), subcerts: Vec::from([]) });
        return true
    }

    for crt in cert.subcerts.as_mut_slice() {
        return recurse_add(crt, cname, auth_cname);
    }

    false
}



