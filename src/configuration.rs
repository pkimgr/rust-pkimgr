use serde::{Deserialize, Serialize};

use crate::certificates::X509CertEntries;

#[derive(Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub x509_certs_entries: X509CertEntries,
}

pub const DEFAULT_CONFIGURATION: &str = r#"
{
    "x509_certs_entries": {
        "country": "UK",
        "state": "UK",
        "organization": "PoweredByPKImgr",
        "validity": 365
    }
}"#;