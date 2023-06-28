extern crate crossterm;

#[macro_use]
extern crate clap;

extern crate yubihsmrs;
extern crate crossterm_input;
extern crate openssl;

use std::io::{Write, stdin, stdout};
use clap::{App, AppSettings, Arg, SubCommand};
use yubihsmrs::{Session, YubiHsm};
use util::{get_integer, get_string, parse_id};

pub mod util;
pub mod asym_commands;

fn is_valid_id(value: String) -> Result<(), String> {
    // NOTE(adma): dropping value just to keep the linter quiet, the
    // prototype is dictated by Clap
    parse_id(&value).map(|_| {
        drop(value);
    })
}

fn get_session(hsm: &YubiHsm, open_session:bool, authkey:u16, password:String) -> Option<Session> {
    if !open_session {
        None
    } else {
        Some(hsm
            .establish_session(authkey, &password, true)
            .unwrap_or_else(|err| {
                println!("Unable to open session: {}", err);
                std::process::exit(1);
            }))
    }
}

fn get_session_option(open_session:bool, authkey:u16, password:String) -> Option<Session>{
    yubihsmrs::init().unwrap_or_else(|err| {
        println!("Unable to initialize libyubihsm: {}", err);
        std::process::exit(1);
    });

    //let h = YubiHsm::new(connector).unwrap_or_else(|err| {
    let h = YubiHsm::new("http://127.0.0.1:12345").unwrap_or_else(|err| {
        println!("Unable to create HSM object: {}", err);
        std::process::exit(1);
    });

    //h.set_verbosity(matches.is_present("verbose"))
    h.set_verbosity(false)
        .unwrap_or_else(|err| {
            println!("Unable to set verbosity: {}", err);
            std::process::exit(1);
        });

    //let session = get_session(&h, open_session, authkey, password);
    let mut session:Option<Session> =
        if !open_session {
            None
        } else {
            Some(h
                .establish_session(authkey, &password, true)
                .unwrap_or_else(|err| {
                    println!("Unable to open session: {}", err);
                    std::process::exit(1);
                }))
        };
    session
}

fn main() -> Result<(), yubihsmrs::error::Error> {

    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommands(vec![
            SubCommand::with_name("auth").about("Manage users"),
            SubCommand::with_name("asym").about("Manage asymmetric keys"),
            SubCommand::with_name("wrap").about("Manage wrap keys"),
            SubCommand::with_name("random").about("Get pseudo-random data from device"),
        ]).arg(
        Arg::with_name("no-auth")
            .long("no-auth")
            .short("a")
            .help("Don't open a session with the device"),
    ).arg(
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
    let open_session = !matches.is_present("no-auth");

    let mut authkey:u16 = 1;
    let mut password:String = String::from("password");
    if open_session {
        //let authkey = parse_id(matches.value_of("authkey").unwrap()).unwrap();
        authkey = match matches.value_of("authkey") {
            Some(authkey) => parse_id(matches.value_of("authkey").unwrap()).unwrap(),
            None => get_integer("Login with authentication key ID [default 1]: ", true, 1),
        };
        password = match matches.value_of("password") {
            Some(password) => password.to_owned(),
            None => get_string("Enter authentication password [default 'password']: ", "password"),
        };
        println!("Using authentication key 0x{:04x}", authkey);
    }

    yubihsmrs::init().unwrap_or_else(|err| {
        println!("Unable to initialize libyubihsm: {}", err);
        std::process::exit(1);
    });

    let h = YubiHsm::new(connector).unwrap_or_else(|err| {
        println!("Unable to create HSM object: {}", err);
        std::process::exit(1);
    });


    let s:Session;
    //let session = get_session(&h, open_session, authkey, password);
    let session:Option<&Session> =
        if !open_session {
            None
        } else {
            h.set_verbosity(matches.is_present("verbose"))
                .unwrap_or_else(|err| {
                    println!("Unable to set verbosity: {}", err);
                    std::process::exit(1);
                });

            s = h
                .establish_session(authkey, &password, true)
                .unwrap_or_else(|err| {
                    println!("Unable to open session: {}", err);
                    std::process::exit(1);
                });
            Some(&s)
        };


    match matches.subcommand_name() {
        Some("auth") => asym_commands::exec_asym_command(session)?,
        Some("asym") => asym_commands::exec_asym_command(session)?,
        Some("wrap") => asym_commands::exec_asym_command(session)?,
        Some("random") => asym_commands::exec_asym_command(session)?,
        _ => unreachable!(),
    }

    println!("All done");
    Ok(())

}