# rust Pkimgr

Simple PKI manager CLI.

With this project, you'll be able to create your own PKI !

## Installation

Download the source and compile with
``` $ cargo build ```

To install  pkimgr tool (untested yet):
```$ cargo install ```

## Options
```
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

Simple PKI generator

Usage: pkimgr [OPTIONS] <PKI_FILE>

Arguments:
  <PKI_FILE>  Path of the file describing the PKI

Options:
  -p, --path <PATH>                              Path to store the PKI [default: output]
  -c, --configuration-file <CONFIGURATION_FILE>  Path of the configuration file to use [default: ]
  -h, --help                                     Print help
  -V, --version                                  Print version
```

## More informations
You can visit our [wiki](https://gitlab.com/pkimgr/python/python-pkimgr/-/wikis/home) for more informations about PKI h

## Roadmap
- Be able to read pki specifications from file
- Specify cert utility
- embeed on pkcs12 or pkcs8
- Rework structs to be able to dot chain creation