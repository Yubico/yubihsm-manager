extern crate base64;
extern crate clap;
extern crate cliclack;
extern crate console;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate pem;
extern crate regex;
extern crate rusty_secrets;
extern crate scan_dir;
extern crate serde;
extern crate yubihsmrs;


use std::str::FromStr;

use clap::Arg;
use yubihsmrs::{Session, YubiHsm};

use error::MgmError;
use util::get_ec_privkey_from_pemfile;
use util::list_objects;

pub mod error;
pub mod util;
pub mod asym_commands;
pub mod sym_commands;
pub mod auth_commands;
pub mod wrap_commands;

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
const YH_EC_P256_PRIVKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum MainCommand {
    #[default]
    ListObjects,
    AuthMgm,
    AsymMgm,
    SymMgm,
    WrapMgm,
    Random,
    Reset,
    Exit,
}

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

fn get_random_number(session: &Session) -> Result<(), MgmError> {
    let nr_of_bytes: usize = cliclack::input("Enter number of bytes")
        .default_input("256")
        .required(false)
        .placeholder("Can be maximum of 2028 bytes for newer YubiHSMs or 2021 for older ones. Default is 256")
        .validate(|input: &String| {
            if usize::from_str(input).is_err() {
                Err("Input must be a number number")
            } else if usize::from_str(input).unwrap() > 2028 {
                Err("The number must be no greater than 2028 for newer YubiHSMs or 2021 for older ones")
            } else {
                Ok(())
            }
        })
        .interact()?;
    match session.get_random(nr_of_bytes) {
        Ok(random) => cliclack::log::success(hex::encode(random))?,
        Err(err) => {
            cliclack::log::error(format!("Failed to get pseudo random number from device. {}", err))?;
        }
    }
    Ok(())
}

fn reset_device(session: &Session) -> Result<(), MgmError> {
    cliclack::log::warning("All data will be deleted from the device and cannot be recovered.")?;
    if cliclack::confirm("Continue?").interact()? {
        if let Err(err) = session.reset() {
            cliclack::log::error(format!("Failed to reset device. {}", err))?;
        };
    }
    Ok(())
}

fn main() -> Result<(), MgmError>{
    let matches = clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(clap::Command::new("get-device-info").about("Display YubiHSM device info"))
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
        let info = unwrap_or_exit1!(h.get_device_info(), "Unable to get device info");
        cliclack::log::success(info)?;
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
        let privkey = get_ec_privkey_from_pemfile(filename)?;
        if privkey.len() != YH_EC_P256_PRIVKEY_LEN {
            cliclack::log::error("Wrong length of private key").unwrap();
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


    loop {
        let command = cliclack::select("")
            .item(MainCommand::ListObjects, "List all objects", "")
            .item(MainCommand::AsymMgm, "Manage asymmetric keys", "")
            .item(MainCommand::SymMgm, "Manage symmetric keys", "Available with firmware version 2.3.1 or later")
            .item(MainCommand::AuthMgm, "Manage authentication keys", "")
            .item(MainCommand::WrapMgm, "Manage wrap keys", "")
            .item(MainCommand::Random, "Generate pseudo random number", "")
            .item(MainCommand::Reset, "Reset device", "")
            .item(MainCommand::Exit, "Exit", "")
            .interact()?;

        let result = match command {
            MainCommand::ListObjects => {
                match session.list_objects() {
                    Ok(objects ) => list_objects(&session, &objects),
                    Err(err) => Err(MgmError::LibYubiHsm(err)),
                }
            },
            MainCommand::AsymMgm => asym_commands::exec_asym_command(&session, authkey),
            MainCommand::SymMgm => sym_commands::exec_sym_command(&session, authkey),
            MainCommand::AuthMgm => auth_commands::exec_auth_command(&session, authkey),
            MainCommand::WrapMgm => wrap_commands::exec_wrap_command(&session, authkey),
            MainCommand::Random => get_random_number(&session),
            MainCommand::Reset => reset_device(&session),
            MainCommand::Exit => std::process::exit(0),
        };

        if let Err(err) = result {
            cliclack::log::error(err)?;
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