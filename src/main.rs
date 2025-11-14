/*
 * Copyright 2025 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate base64;
extern crate clap;
extern crate cliclack;
extern crate console;
extern crate hex;
extern crate openssl;
extern crate pem;
extern crate regex;
extern crate rusty_secrets;
extern crate scan_dir;
extern crate serde;
extern crate yubihsmrs;
extern crate comfy_table;
extern crate core;


use std::fs;
use clap::Arg;
use yubihsmrs::YubiHsm;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use backend::asym::AsymOps;
use backend::error::MgmError;
pub mod backend;
pub mod ui;

macro_rules! unwrap_or_exit1 {
    ( $e:expr, $msg:expr) => {
        match $e {
            Ok(x) => x,
            Err(err) => {
                cliclack::log::error(format!("{}. {}", $msg, err))?;
                std::process::exit(1);
            },
        }
    }
}

const YH_EC_P256_PUBKEY_LEN: usize = 65;

pub static MAIN_HEADER: &str = "YubiHSM Manager";

fn parse_id(value: &str) -> Result<u16, String> {
    let id = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)
    } else {
        value.parse()
    };

    match id {
        Ok(id) => Ok(id),
        Err(_) => Err("ID must be a number in [1, 65535]".to_string()),
    }
}

fn main() -> Result<(), MgmError>{
    let matches = clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(clap::Command::new("get-device-info").about("Display YubiHSM device info"))
        .subcommand(clap::Command::new("get-device-publickey").about("Display YubiHSM device public key"))
        .subcommand(clap::Command::new("asym").about("Manage asymmetric keys"))
        .subcommand(clap::Command::new("sym").about("Manage symmetric keys"))
        .subcommand(clap::Command::new("auth").about("Manage authentication keys (aka users)"))
        .subcommand(clap::Command::new("wrap").about("Manage wrap keys"))
        .subcommand(clap::Command::new("reset").about("Reset YubiHSM2 device"))
        .subcommand(clap::Command::new("ksp").about("Setup KSP user for Windows CNG provider"))
        .subcommand(clap::Command::new("sunpkcs11").about("Manage asymmetric keys compatible with JAVA SunPKCS11 provider"))
        .arg(Arg::new("authkey")
            .long("authkey")
            .short('k')
            .help("Authentication key to open a session with the device")
            .default_value("1")
            .hide_default_value(false))
        .arg(Arg::new("privkey")
            .long("privkey")
            .short('d')
            .help("Path to PEM file containing ECP256 private key used to open an asymmetric session"))
        .arg(Arg::new("password")
            .long("password")
            .short('p')
            .help("Password to open a session with the device"))
        .arg(Arg::new("connector")
            .long("connector")
            .short('c')
            .help("Connector URL")
            .default_value("http://127.0.0.1:12345")
            .hide_default_value(false))
        .arg(Arg::new("verbose")
            .long("verbose")
            .short('v')
            .help("Produce more debug output")
            .num_args(0)
            .default_value("false")
            .action(clap::ArgAction::SetTrue))
        .get_matches();

    let Some(connector) = matches.get_one::<String>("connector") else {
        cliclack::log::error("Failed to read connector value")?;
        std::process::exit(1);
    };

    if let Err(err) = yubihsmrs::init() {
        cliclack::log::error(format!("Unable to initialize libyubihsm: {}", err))?;
        std::process::exit(1);
    };

    let h = unwrap_or_exit1!(YubiHsm::new(connector), "Unable to create HSM object");

    if let Err(err) = h.set_verbosity(matches.get_flag("verbose")) {
        cliclack::log::error(format!("Unable to set verbosity: {}", err))?;
        std::process::exit(1);
    };

    if let Some("get-device-info") = matches.subcommand_name() {
        let info = h.get_device_info()?;
        cliclack::log::success(info)?;
        return Ok(());
    };

    if let Some("get-device-publickey") = matches.subcommand_name() {
        let pubkey = h.get_device_pubkey()?;
        let pubkey = AsymOps::get_pubkey_pem(ObjectAlgorithm::EcP256, &pubkey)?;
        println!("{}\n",pubkey);
        return Ok(());
    };

    let authkey = match matches.get_one::<String>("authkey") {
        Some(auth_key) => {
            parse_id(auth_key).unwrap_or_else(|err| {
                cliclack::log::error(format!("Unable to parse authentication key ID: {}", err)).unwrap();
                std::process::exit(1);
            })
        },
        None => 1,
    };

    cliclack::log::info(format!("Using authentication key 0x{:04x}", authkey))?;

    let session =
    if matches.contains_id("privkey") {
        let filename = match matches.get_one::<String>("privkey") {
            Some(filename) => filename.to_owned(),
            None => {
                cliclack::log::error("Unable to read private key file name").unwrap();
                std::process::exit(1);
            },
        };

        let (_typ, _algo, privkey) = AsymOps::parse_asym_pem(pem::parse(fs::read_to_string(filename)?)?)?;
        if _typ != ObjectType::AsymmetricKey || _algo != ObjectAlgorithm::EcP256 {
            cliclack::log::error("Private key in PEM file is not an EC P256 key")?;
            std::process::exit(1);
        }
        let device_pubkey = h.get_device_pubkey()?;
        if device_pubkey.len() != YH_EC_P256_PUBKEY_LEN {
            cliclack::log::error("Wrong length of device public key").unwrap();
            std::process::exit(1);
        }
        unwrap_or_exit1!(h.establish_session_asym(authkey, privkey.as_slice(), device_pubkey.as_slice()), "Unable to open asymmetric session")
    } else {
        let password = match matches.get_one::<String>("password") {
            Some(password) => password.to_owned(),
            None => {
                cliclack::password("Enter authentication password:")
                    .mask('*')
                    .interact()?
            },
        };
        unwrap_or_exit1!(h.establish_session(authkey, &password, true), "Unable to open session")
    };

    let authkey = session.get_object_info(authkey, ObjectType::AuthenticationKey)?;

    match matches.subcommand() {
        Some(subcommand) => {
            match subcommand.0 {
                "asym" => ui::asym_menu::exec_asym_command(&session, &authkey),
                "sym" => ui::sym_menu::exec_sym_command(&session, &authkey),
                "auth" => ui::auth_menu::exec_auth_command(&session, &authkey),
                "wrap" => ui::wrap_menu::exec_wrap_command(&session, &authkey),
                "reset" => ui::device_menu::reset(&session),
                "ksp" => ui::ksp_menu::guided_ksp_setup(&session, &authkey),
                "sunpkcs11" => ui::java_menu::exec_java_command(&session, &authkey),
                _ => unreachable!(),
            }
        },
        None => {
            ui::main_menu::exec_main_command(&session, &authkey)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_test() {
        let id = parse_id("0");
        assert_eq!(id, Ok(0));
        let id = parse_id("100");
        assert_eq!(id, Ok(100));
        let id = parse_id("0x64");
        assert_eq!(id, Ok(100));
        let id = parse_id("6553564");
        assert!(id.is_err());
        let id = parse_id("ID");
        assert!(id.is_err());
    }
}