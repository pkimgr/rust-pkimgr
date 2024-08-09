use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Configuration <'a> {
    pub country: &'a str,
    pub state: &'a str,
    pub organization: &'a str,
    pub validity: u32,
}

pub const DEFAULT_CONFIGURATION: &str = r#"
{
    "country": "UK",
    "state": "UK",
    "organization": "PoweredByPKImgr",
    "validity": 365
}"#;