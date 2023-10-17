extern crate yubihsmrs;
extern crate openssl;
extern crate pem;
extern crate serde;
extern crate hex;
extern crate base64;
extern crate rusty_secrets;
extern crate regex;
extern crate scan_dir;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate clap;
extern crate cliclack;

use std::str::FromStr;
use clap::{App, AppSettings, Arg, SubCommand};
use yubihsmrs::{YubiHsm};
use error::MgmError;
use util::get_id;

pub mod error;
pub mod util;
pub mod asym_commands;
pub mod auth_commands;
pub mod wrap_commands;

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

fn is_valid_id(value: String) -> Result<(), String> {
    // NOTE(adma): dropping value just to keep the linter quiet, the
    // prototype is dictated by Clap
    // TODO (aveen): Check if this is still necessary
    parse_id(&value).map(|_| {
        drop(value);
    })
}

fn main() -> Result<(), MgmError> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommands(vec![
            SubCommand::with_name("auth").about("Manage users"),
            SubCommand::with_name("asym").about("Manage asymmetric keys"),
            SubCommand::with_name("wrap").about("Manage wrap keys (not implemented yet)"),
            SubCommand::with_name("random").about("Get pseudo-random data from device"),
            SubCommand::with_name("reset").about("Resets the device"),
        ]).arg(
        Arg::with_name("authkey")
            .long("authkey")
            .short("k")
            .help("Authentication key to open a session with the device")
            .default_value("1")
            .takes_value(true)
            .hide_default_value(false)
            .validator(is_valid_id),
    ).arg(
        Arg::with_name("password")
            .long("password")
            .short("p")
            .help("Password to open a session with the device")
            .takes_value(true),
    ).arg(
        Arg::with_name("connector")
            .long("connector")
            .short("c")
            .help("Connector URL")
            .default_value("http://127.0.0.1:12345")
            .takes_value(true)
            .hide_default_value(false),
    ).arg(
        Arg::with_name("verbose")
            .long("verbose")
            .short("v")
            .help("Produce more debug output"),
    ).get_matches();

    let connector = matches.value_of("connector").unwrap();

    let mut authkey: u16 = 1;
    let mut password: String = "password".to_string();

    authkey = match matches.value_of("authkey") {
        Some(auth_key) => parse_id(auth_key).unwrap(),
        None => get_id("Login with authentication key ID [default 1]: ", "1"),
    };
    password = match matches.value_of("password") {
        Some(password) => password.to_owned(),
        None => {
            cliclack::password("Enter authentication password:")
                .mask('*')
                .interact()?
        },
    };
    cliclack::log::info(format!("Using authentication key 0x{:04x}", authkey)).unwrap();


    yubihsmrs::init().unwrap_or_else(|err| {
        cliclack::log::error(format!("Unable to initialize libyubihsm: {}", err)).unwrap();
        std::process::exit(1);
    });

    let h = YubiHsm::new(connector).unwrap_or_else(|err| {
        cliclack::log::error(format!("Unable to create HSM object: {}", err)).unwrap();
        std::process::exit(1);
    });

    h.set_verbosity(matches.is_present("verbose"))
        .unwrap_or_else(|err| {
            cliclack::log::error(format!("Unable to set verbosity: {}", err)).unwrap();
            std::process::exit(1);
        });

    let session = h
        .establish_session(authkey, &password, true)
        .unwrap_or_else(|err| {
            cliclack::log::error(format!("Unable to open session: {}", err)).unwrap();
            std::process::exit(1);
        });

    match matches.subcommand_name() {
        Some("auth") => auth_commands::exec_auth_command(&session, authkey)?,
        Some("asym") => asym_commands::exec_asym_command(&session, authkey)?,
        Some("wrap") => wrap_commands::exec_wrap_command(&session, authkey)?,
        Some("random") => {
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
            let random = hex::encode(session.get_random(nr_of_bytes)?);
            cliclack::log::success(random)?;
        }
        Some("reset") => session.reset()?,
        _ => return Err(MgmError::Error("Unrecognized subcommand".to_string())),
    }

    println!("All done");
    Ok(())
}