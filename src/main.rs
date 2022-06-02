/*
 * Copyright 2015-2018 Yubico AB
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

extern crate rusty_secrets;
extern crate yubihsmrs;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate lazy_static;

extern crate regex;

extern crate hex;

use regex::Regex;

use std::io;
use std::io::Write;

use yubihsmrs::YubiHsm;

use clap::{App, AppSettings, Arg, SubCommand};


lazy_static! {
    static ref SHARE_RE: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap();
}

#[derive(Debug)]
enum BooleanAnswer {
    Yes,
    No,
}

impl BooleanAnswer {
    fn from_str(value: &str) -> Result<BooleanAnswer, String> {
        let lowercase = value.to_lowercase();
        match lowercase.as_ref() {
            "y" | "yes" => Ok(BooleanAnswer::Yes),
            "n" | "no" => Ok(BooleanAnswer::No),
            _ => Err(format!("Unable to parse {}", value)),
        }
    }
}

impl From<BooleanAnswer> for bool {
    fn from(ba: BooleanAnswer) -> bool {
        match ba {
            BooleanAnswer::Yes => true,
            BooleanAnswer::No => false,
        }
    }
}

fn read_line_or_die() -> String {
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(_) => line.trim().to_owned(),
        Err(err) => {
            println!("Unable to read from stdin: {}", err);
            std::process::exit(1)
        }
    }
}

#[cfg(target_os = "windows")]
fn clear_screen() {
    std::process::Command::new("cmd")
        .args(&["/C", "cls"])
        .status()
        .unwrap_or_else(|err| {
            println!("Unable to clear terminal screen: {}", err);
            std::process::exit(1);
        });
}

#[cfg(not(target_os = "windows"))]
fn clear_screen() {
    std::process::Command::new("clear")
        .status()
        .unwrap_or_else(|err| {
            println!("Unable to clear terminal screen: {}", err);
            std::process::exit(1);
        });
}

fn get_boolean_answer(prompt: &str) -> BooleanAnswer {
    loop {
        print!("{} (y/n) ", prompt);
        std::io::stdout().flush().expect("Unable to flush stdout");
        match BooleanAnswer::from_str(&read_line_or_die()) {
            Ok(a) => {
                break a;
            }
            _ => {
                continue;
            }
        }
    }
}

fn parse_id(value: &str) -> Result<u16, String> {
    let id = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)
    } else {
        value.parse::<u16>()
    };

    if id.is_ok() {
        let id = id.unwrap();
        if id != 0 {
            return Ok(id);
        }
    }

    Err("ID must be a number in [1, 65535]".to_string())
}

fn is_valid_id(value: String) -> Result<(), String> {
    // NOTE(adma): dropping value just to keep the linter quiet, the
    // prototype is dictated by Clap
    parse_id(&value).map(|_| {
        drop(value);
    })
}

fn get_string(prompt: &str) -> String {
    print!("{} ", prompt);
    std::io::stdout().flush().expect("Unable to flush stdout");
    read_line_or_die()
}

fn manage_auth(session: &yubihsmrs::Session, auth_id: u16) {
    println!("Subcommand to manage authentication keys")
}

fn manage_asym(session: &yubihsmrs::Session, auth_id: u16) {
    println!("Subcommand to manage asymmetric keys")
}

fn manage_wrap(session: &yubihsmrs::Session, auth_id: u16) {
    println!("Subcommand to manage wrap keys")
}

fn get_random(session: &yubihsmrs::Session, auth_id: u16) {
    let rand = session.get_random(256).unwrap_or_else(|err| {
        println!("Unable to generate random data: {}", err);
        std::process::exit(1);
    });
    let s = hex::encode(rand);
    println!("{}", s)
}

fn reset_device(session: &yubihsmrs::Session, forced: bool) {
    if !forced
        && !Into::<bool>::into(get_boolean_answer(
        "This will erase the content of the device. Are you sure?",
    ))
    {
        println!("Reset aborted");
        return;
    }

    session.reset().unwrap_or_else(|err| {
        println!("Unable to reset device: {}", err);
        std::process::exit(1)
    });

    println!("Device successfully reset");
}


fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommands(vec![
            SubCommand::with_name("auth").about("Manage Authentication keys"),
            SubCommand::with_name("asym").about("Manage Asymmetric keys"),
            SubCommand::with_name("wrap").about("Manage Wrap keys"),
            SubCommand::with_name("random").about("Get pseudo-random number"),
            SubCommand::with_name("reset").about("Reset the device")
                .arg(
                    Arg::with_name("force")
                        .long("force")
                        .short("f")
                        .help("Do not ask for confirmation during reset"),
                ),
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
    let authkey = parse_id(matches.value_of("authkey").unwrap()).unwrap();
    let password = match matches.value_of("password") {
        Some(password) => password.to_owned(),
        None => get_string("Enter authentication password:"),
    };

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

    println!("Using authentication key 0x{:04x}", authkey);

    let session = h
        .establish_session(authkey, &password, true)
        .unwrap_or_else(|err| {
            println!("Unable to open session: {}", err);
            std::process::exit(1);
        });

    match matches.subcommand_name() {
        Some("auth") => manage_auth(
            &session,
            authkey,
        ),
        Some("asym") => manage_asym(
            &session,
            authkey,
        ),
        Some("wrap") => manage_wrap(
            &session,
            authkey,
        ),
        Some("random") => get_random(
            &session,
            authkey,
        ),
        Some("reset") => reset_device(
            &session,
            matches
                .subcommand_matches("reset")
                .unwrap()
                .is_present("force"),
        ),
        None => println!("Unsupported subcommand!"),
        Some(&_) => println!("Unsupported subcommand!")
    }

    println!("All done")
}
