extern crate crossterm;

#[macro_use]
extern crate clap;

extern crate yubihsmrs;
extern crate crossterm_input;
extern crate openssl;
extern crate pem;
extern crate crossterm_utils;
extern crate crossterm_screen;
extern crate serde;

use std::fmt::format;
use std::io::{Write, stdin, stdout};
use clap::{App, AppSettings, Arg, SubCommand};
use yubihsmrs::{Session, YubiHsm};
use error::MgmError;
use util::{get_integer_or_default, get_string, get_string_or_default, parse_id};

pub mod error;
pub mod util;
pub mod asym_commands;
pub mod auth_commands;

fn is_valid_id(value: String) -> Result<(), String> {
    // NOTE(adma): dropping value just to keep the linter quiet, the
    // prototype is dictated by Clap
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
        Some(authkey) => parse_id(matches.value_of("authkey").unwrap()).unwrap(),
        None => get_integer_or_default("Login with authentication key ID [default 1]: ", 1),
    };
    password = match matches.value_of("password") {
        Some(password) => password.to_owned(),
        None => get_string_or_default("Enter authentication password [default 'password']: ", "password"),
    };
    println!("Using authentication key 0x{:04x}", authkey);


    yubihsmrs::init().unwrap_or_else(|err| {
        println!("Unable to initialize libyubihsm: {}", err);
        std::process::exit(1);
    });

    let h = YubiHsm::new(connector).unwrap_or_else(|err| {
        println!("Unable to create HSM object: {}", err);
        std::process::exit(1);
    });

    h.set_verbosity(matches.is_present("verbose"))
        .unwrap_or_else(|err| {
            println!("Unable to set verbosity: {}", err);
            std::process::exit(1);
        });

    let session = h
        .establish_session(authkey, &password, true)
        .unwrap_or_else(|err| {
            println!("Unable to open session: {}", err);
            std::process::exit(1);
        });

    match matches.subcommand_name() {
        Some("auth") => auth_commands::exec_auth_command(&session, authkey)?,
        Some("asym") => asym_commands::exec_asym_command(&session, authkey)?,
        //Some("wrap") => asym_commands::exec_asym_command(session, authkey)?,
        Some("random") => {
            let nr_of_bytes:usize = get_integer_or_default("  Enter number of bytes [default 256]:", 256);
            for b in session.get_random(nr_of_bytes)? {
                print!("{b:02x}");
            }
            println!();
        }
        Some("reset") => session.reset()?,
        _ => return Err(MgmError::Error("Unrecognized subcommand".to_string())),
    }

    println!("All done");
    Ok(())
}