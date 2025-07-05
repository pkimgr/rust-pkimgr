use serde::{Deserialize, Serialize};

use crate::certificates::X509Info;

pub mod certificates;
pub mod key;
pub mod pki;

pub mod cli;
pub mod error;

pub const BANNER: &str = r#"
           __                    __  ____      __         __
          / /__  ____ _____     /  |/  (_)____/ /_  ___  / /
     __  / / _ \/ __ `/ __ \   / /|_/ / / ___/ __ \/ _ \/ /
    / /_/ /  __/ /_/ / / / /  / /  / / / /__/ / / /  __/ /
    \____/\___/\__,_/_/ /_/  /_/  /_/_/\___/_/ /_/\___/_/
        ____  __ __ ____
       / __ \/ //_//  _/___ ___  ____ ______
      / /_/ / ,<   / // __ `__ \/ __ `/ ___/
     / ____/ /| |_/ // / / / / / /_/ / /
    /_/   /_/ |_/___/_/ /_/ /_/\__, /_/
          rust edition        /____/
"#;

const PEM_DIR: &'static str = "private";
const CERTS_DIR: &'static str = "certs";


pub const DEFAULT_CONFIGURATION: &str = r#"
{
    "x509_certs_entries": {
        "country": "UK",
        "state": "UK",
        "organization": "PoweredByPKImgr",
        "validity": 365
    }
}"#;

#[derive(Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub x509_certs_entries: X509Info,
}