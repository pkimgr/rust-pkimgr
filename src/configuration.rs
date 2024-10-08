use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub country: String,
    pub state: String,
    pub organization: String,
    pub validity: u32,
}

pub const DEFAULT_CONFIGURATION: &str = r#"
{
    "country": "UK",
    "state": "UK",
    "organization": "PoweredByPKImgr",
    "validity": 365
}"#;