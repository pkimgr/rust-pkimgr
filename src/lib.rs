use std::{
    collections::HashMap,
    path::Path
};

use crate::{certificates::CertBuilders, pki::Pki};

pub mod certificates;
pub mod configuration;
pub mod pki;

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



pub struct Pkimgr<'a> {
    pki: HashMap<String, Pki<'a>>,
}

impl <'a> Pkimgr<'a> {
    pub fn new() ->  Pkimgr<'a> {
        Pkimgr {
            pki: HashMap::new()
        }
    }

    pub fn new_pki(&mut self, pki_path: &'a Path, cert_builder: &'a CertBuilders) -> &Self {
        self.pki.insert(
            String::from(pki_path.to_str().unwrap()),
            Pki::new(cert_builder,  pki_path)
                .expect("cannot create new pki")
        );

        self
    }

    pub fn pki_len(&self) -> usize {
        self.pki.len()
    }

    pub fn list_pki(&self) -> &HashMap<String, Pki> {
        &self.pki
    }
}

