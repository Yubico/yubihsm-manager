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

use clap::Arg;
use yubihsmrs::YubiHsm;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use hsm_operations::asym::AsymmetricOperations;
use hsm_operations::common::get_id_from_string;
use hsm_operations::error::MgmError;
use hsm_operations::validators::pem_private_ecp256_file_validator;
use traits::ui_traits::YubihsmUi;
use ui::helper_io::get_pem_from_file;
use cli::cmdline::Cmdline;
use script::script_recorder::{RedactMode, SessionRecorder};
use script::script_runner::{ScriptRunner};
use script::types::{SessionScript};
use ui::asym_menu::AsymmetricMenu;
use ui::auth_menu::AuthenticationMenu;
use ui::device_menu::DeviceMenu;
use ui::java_menu::JavaMenu;
use ui::ksp_menu::Ksp;
use ui::main_menu::MainMenu;
use ui::sym_menu::SymmetricMenu;
use ui::wrap_menu::WrapMenu;

pub mod hsm_operations;
pub mod ui;
pub mod traits;
pub mod cli;
pub mod script;


macro_rules! unwrap_or_exit1 {
    ( $e:expr, $msg:expr) => {
        match $e {
            Ok(x) => x,
            Err(err) => {
                YubihsmUi::display_error_message(&Cmdline, format!("{}. {}", $msg, err).as_str());
                std::process::exit(1);
            },
        }
    }
}

const YH_EC_P256_PUBKEY_LEN: usize = 65;

pub static MAIN_HEADER: &str = "YubiHSM Manager";

fn main() -> Result<(), MgmError>{

    let ui = Cmdline::new();


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

        .arg(Arg::new("record")
            .long("record")
            .short('r')
            .help("Record session operations in a script for later execution. Use the --redact option to redact sensitive values in the recorded script")
            .num_args(1)
            .value_name("file-suffix")
            // .default_value("")
            .help_heading("Scripting"))
        .arg(Arg::new("exec")
            .long("exec")
            .short('e')
            .help("Execute operations from a recorded script file")
            .value_name("file")
            .num_args(1)
            .conflicts_with("record")
            .help_heading("Scripting"))
        .arg(Arg::new("continue-on-error")
            .long("continue-on-error")
            .help("If an error occurs during script execution, print out a warning and continue executing the next operation. Default is to exit on error.")
            .num_args(0)
            .default_value("false")
            .action(clap::ArgAction::SetTrue)
            .help_heading("Scripting"))
        .arg(Arg::new("redact")
            .long("redact")
            .help("Redact sensitive values when recording a script. Default is only new Authentication Key value (password and private ECP256 key) are redacted. Redacted data will be prompted for when executing a script")
            .value_parser(clap::builder::EnumValueParser::<RedactMode>::new())
            .default_value("sensitive")
            .requires("record")
            .help_heading("Scripting"))
        .get_matches();

    // Check if we are executing a script or entering into command line mode
    let script: Option<SessionScript> = if let Some(script_path) = matches.get_one::<String>("exec") {
        let s = ScriptRunner::load(std::path::Path::new(script_path))?;

        ui.display_info_message(&format!(
            "Loaded script with {} operations", s.operations.len()));
        Some(s)
    } else {
        None
    };

    // Connector value is needed to create the HSM object. Priority: command line > script > default.
    let connector =
    if let Some(c) = matches.get_one::<String>("connector") {
        c
     } else if let Some(s) = &script {
        &s.session.connector
     } else {
        YubihsmUi::display_error_message(&ui, "Failed to read connector value");
        std::process::exit(1);
    };

    unwrap_or_exit1!(yubihsmrs::init(), "Unable to initialize libyubihsm");
    let h = unwrap_or_exit1!(YubiHsm::new(connector), "Unable to create HSM object");
    unwrap_or_exit1!(h.set_verbosity(matches.get_flag("verbose")), "Unable to set verbosity");

    // This command does not require authentication
    if let Some("get-device-info") = matches.subcommand_name() {
        let info = h.get_device_info()?;
          println!("{}\n", info);
        return Ok(());
    };

    // This command does not require authentication
    if let Some("get-device-publickey") = matches.subcommand_name() {
        let pubkey = h.get_device_pubkey()?;
        let pubkey = AsymmetricOperations::get_pubkey_pem(ObjectAlgorithm::EcP256, &pubkey)?;
        println!("{}\n", pubkey);
        return Ok(());
    };

    // Determine authentication key ID to use for session. Priority: command line > script > default (1).
    let authkey =
        if let Some(id) = matches.get_one::<String>("authkey") {
            get_id_from_string(id)?
        } else if let Some(s) = &script {
            s.session.auth_key_id
        } else {
            1
        };
    YubihsmUi::display_info_message(&ui, format!("Using authentication key 0x{:04x}", authkey).as_str());

    // Open a session authenticated either by a password or a private ECP256 key
    let session =
    if matches.contains_id("privkey") {
        let filename = if let Some(f) = matches.get_one::<String>("privkey") {
            f.to_owned()
        } else {
            YubihsmUi::display_error_message(&ui, "Unable to read private key file name");
            std::process::exit(1);
        };

        if pem_private_ecp256_file_validator(&filename).is_err() {
            YubihsmUi::display_error_message(&ui, "Private key in PEM file is not a private EC P256 key");
            std::process::exit(1);
        }

        let pems = get_pem_from_file(&filename)?;
        if pems.len() > 1 {
            YubihsmUi::display_warning(&ui, "Warning!! More than one PEM object found in file. Only the first object is read");
        }
        let (_, _, privkey) = AsymmetricOperations::parse_asym_pem(pems[0].clone())?;
        let device_pubkey = h.get_device_pubkey()?;
        if device_pubkey.len() != YH_EC_P256_PUBKEY_LEN {
            YubihsmUi::display_error_message(&ui, "Wrong length of device public key");
            std::process::exit(1);
        }
        unwrap_or_exit1!(h.establish_session_asym(authkey, privkey.as_slice(), device_pubkey.as_slice()), "Unable to open asymmetric session")
    } else {
        let password = if let Some(pwd) = matches.get_one::<String>("password") {
            pwd.to_owned()
        } else {
            YubihsmUi::get_password(&ui, "Enter authentication password:", false)?
        };

        if authkey == 1 && password == "password" {
            YubihsmUi::display_warning(&ui, "Warning!! Opening a session using default authentication key and default password. It is strongly recommended to change default credentials");
        }
        unwrap_or_exit1!(h.establish_session(authkey, &password, true), "Unable to open session")
    };

    // If a script was loaded, execute it and exit — skip interactive menu.
    if let Some(s) = &script {
        YubihsmUi::display_info_message(&ui, "Executing script...");
        if let Err(e) = ScriptRunner::run(&ui, &session, s, matches.get_flag("continue-on-error")) {
            YubihsmUi::display_error_message(&ui,e.to_string().as_str());
        }
        return Ok(())
    }

    let recorder: Option<SessionRecorder> =
    if let Some(script_suffix) = matches.get_one::<String>("record") {
        YubihsmUi::display_info_message(&ui, "Starting session recording...");
        let mode = matches.get_one::<RedactMode>("redact").cloned().unwrap_or_default();  // defaults to RedactMode::AuthOnly
        Some(SessionRecorder::new(
            connector.clone(),
            authkey,
            script_suffix.to_owned(),
            mode,
        ))
    } else {
        None
    };

    // Enter command line mode
    let authkey = session.get_object_info(authkey, ObjectType::AuthenticationKey)?;

    match matches.subcommand() {
        Some(subcommand) => {
            match subcommand.0 {
                "asym" => AsymmetricMenu::new(ui).exec_command(&session, &recorder, &authkey),
                "sym" => SymmetricMenu::new(ui).exec_command(&session, &recorder, &authkey),
                "auth" => AuthenticationMenu::new(ui).exec_command(&session, &recorder, &authkey),
                "wrap" => WrapMenu::new(ui).exec_command(&session, &recorder, &authkey),
                "ksp" => Ksp::new(ui).guided_setup(&session, &authkey),
                "sunpkcs11" => JavaMenu::new(ui).exec_command(&session, &recorder, &authkey),
                "reset" => DeviceMenu::new(ui).reset(&session),
                _ => unreachable!(),
            }
        },
        None => {
            MainMenu::new(ui).exec_command(&session, &recorder, &authkey)
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn id_test() {
//         let id = parse_id("0");
//         assert_eq!(id, Ok(0));
//         let id = parse_id("100");
//         assert_eq!(id, Ok(100));
//         let id = parse_id("0x64");
//         assert_eq!(id, Ok(100));
//         let id = parse_id("6553564");
//         assert!(id.is_err());
//         let id = parse_id("ID");
//         assert!(id.is_err());
//     }
// }