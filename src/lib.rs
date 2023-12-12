use serde::{Deserialize, Serialize};

pub mod certificates;
pub mod pki;
pub mod pki_serializer;

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