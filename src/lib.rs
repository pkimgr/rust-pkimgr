pub mod certificates;
pub mod key;
pub mod pki;

pub mod configuration;
pub mod cli;
pub mod serializer;

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

const DEFAULT_KEYLEN: u32 = 4096;
const PEM_DIR: &'static str = "private";
const CERTS_DIR: &'static str = "certs";

