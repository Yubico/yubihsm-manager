use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::sync::LazyLock;

use crate::util::{delete_objects};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{get_delegated_capabilities, get_ec_pubkey_from_pem_string, get_new_object_basics, get_password,
           list_objects, print_object_properties, read_string_from_file, select_capabilities};
use ::{MAIN_STRING, YH_EC_P256_PUBKEY_LEN};

static AUTH_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Authentication keys", MAIN_STRING));

const ASYM_USER_CAPABILITIES: [ObjectCapability; 13] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::SignEcdsa,
    ObjectCapability::SignEddsa,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::SignAttestationCertificate,
    ObjectCapability::EncryptEcb,
    ObjectCapability::EncryptCbc,
    ObjectCapability::DecryptEcb,
    ObjectCapability::DecryptCbc,
    ObjectCapability::ExportableUnderWrap,
];

const ASYM_ADMIN_CAPABILITIES: [ObjectCapability; 9] = [
    ObjectCapability::GenerateAsymmetricKey,
    ObjectCapability::PutAsymmetricKey,
    ObjectCapability::DeleteAsymmetricKey,
    ObjectCapability::PutOpaque,
    ObjectCapability::DeleteOpaque,
    ObjectCapability::GenerateSymmetricKey,
    ObjectCapability::PutSymmetricKey,
    ObjectCapability::DeleteSymmetricKey,
    ObjectCapability::ExportableUnderWrap,
];

const AUDITOR_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::GetLogEntries,
    ObjectCapability::ExportableUnderWrap,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AuthKeyType {
    #[default]
    PasswordDerived,
    Ecp256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum UserType {
    #[default]
    AsymUser,
    AsymAdmin,
    Auditor,
    BackupAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AuthCommand {
    #[default]
    List,
    GetKeyProperties,
    Delete,
    SetupUser,
    SetupAdmin,
    SetupAuditor,
    SetupBackupAdmin,
    ReturnToMainMenu,
    Exit,
}

impl Display for AuthCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCommand::List => write!(f, "List"),
            AuthCommand::GetKeyProperties => write!(f, "Print object properties"),
            AuthCommand::Delete => write!(f, "Delete"),
            AuthCommand::SetupUser => write!(f, "Setup asymmetric/symmetric keys user"),
            AuthCommand::SetupAdmin => write!(f, "Setup asymmetric/symmetric keys admin"),
            AuthCommand::SetupAuditor => write!(f, "Setup Auditor"),
            AuthCommand::SetupBackupAdmin => write!(f, "Setup backup admin"),
            AuthCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            AuthCommand::Exit => write!(f, "Exit"),
        }
    }
}

pub fn exec_auth_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {
        println!("\n{}", *AUTH_STRING);

        let cmd = get_auth_command(authkey)?;
        let res = match cmd {
            AuthCommand::List => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::List);
                list(session)
            },
            AuthCommand::GetKeyProperties => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::GetKeyProperties);
                print_key_properties(session)
            },
            AuthCommand::Delete => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::Delete);
                delete(session)
            },
            AuthCommand::SetupUser => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::SetupUser);
                setup_user(session, authkey, UserType::AsymUser)
            },
            AuthCommand::SetupAdmin => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::SetupAdmin);
                setup_user(session, authkey, UserType::AsymAdmin)
            },
            AuthCommand::SetupAuditor => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::SetupAuditor);
                setup_user(session, authkey, UserType::Auditor)
            },
            AuthCommand::SetupBackupAdmin => {
                println!("\n{} > {}\n", *AUTH_STRING, AuthCommand::SetupBackupAdmin);
                setup_user(session, authkey, UserType::BackupAdmin)
            },
            AuthCommand::ReturnToMainMenu => return Ok(()),
            AuthCommand::Exit => std::process::exit(0),
        };

        if let Err(err) = res {
            cliclack::log::error(err)?;
        }
    }
}

fn get_auth_command(authkey: &ObjectDescriptor) -> Result<AuthCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> = authkey.capabilities.clone().into_iter().collect();
    let delegated_capabilities:HashSet<ObjectCapability> = get_delegated_capabilities(authkey).into_iter().collect();

    let mut commands = cliclack::select("");
    commands = commands.item(AuthCommand::List, AuthCommand::List, "");
    commands = commands.item(AuthCommand::GetKeyProperties, AuthCommand::GetKeyProperties, "");
    if capabilities.contains(&ObjectCapability::DeleteAuthenticationKey) {
        commands = commands.item(AuthCommand::Delete,AuthCommand::Delete, "");
    }
    if capabilities.contains(&ObjectCapability::PutAuthenticationKey) {

        if HashSet::from(ASYM_USER_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands = commands.item(
                AuthCommand::SetupUser, AuthCommand::SetupUser, "Can only use asymmetric and symmetric keys");
        }
        if HashSet::from(ASYM_ADMIN_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands = commands.item(
                AuthCommand::SetupAdmin, AuthCommand::SetupAdmin, "Can only manage asymmetric and symmetric keys");
        }
        if delegated_capabilities.contains(&ObjectCapability::GetLogEntries) {
            commands = commands.item(
                AuthCommand::SetupAuditor, AuthCommand::SetupAuditor, "Can only perform audit functions");
        }
        commands = commands.item(
            AuthCommand::SetupBackupAdmin, AuthCommand::SetupBackupAdmin, "Can have all capabilities of the current user");
    }
    commands = commands.item(AuthCommand::ReturnToMainMenu, "Return to main menu", "");
    commands = commands.item(AuthCommand::Exit, AuthCommand::Exit, "");
    Ok(commands.interact()?)
}

fn get_all_auth_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    Ok(session.list_objects_with_filter(
        0,
        ObjectType::AuthenticationKey,
        "",
        ObjectAlgorithm::ANY,
        &Vec::new())?)
}

fn list(session: &Session) -> Result<(), MgmError> {
    list_objects(session, &get_all_auth_keys(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_auth_keys(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_auth_keys(session)?)
}

fn create_authkey(
    session: &Session,
    new_authkey: &ObjectDescriptor,
) -> Result<(), MgmError> {

    let auth_string = new_authkey.to_string()
        .replace("Algorithm: Unknown\t", "")
        .replace("Sequence:  0\t", "")
        .replace("Origin: Generated\t", "")
        .replace("\t", "\n");

    let auth_type = cliclack::select("Select authentication type:")
        .item(AuthKeyType::PasswordDerived, "Password derived", "Session keys are derived from a password")
        .item(AuthKeyType::Ecp256, "EC P256", "Session authenticated using EC key with curve secp256r1")
        .interact()?;

    let mut id: u16 = 0;
    match auth_type {
        AuthKeyType::PasswordDerived => {
            let pwd = get_password("Enter user password:")?;

            cliclack::note("Creating new authentication key with:",
                           auth_string)?;
            if cliclack::confirm("Create key?").interact()? {
                id = session.import_authentication_key(
                    new_authkey.id,
                    &new_authkey.label,
                    &new_authkey.domains,
                    &new_authkey.capabilities,
                    get_delegated_capabilities(new_authkey).as_slice(),
                    pwd.as_bytes())?
            }
        },
        AuthKeyType::Ecp256 => {
            let (pubkey, _) = get_ec_pubkey_from_pem_string(
                read_string_from_file("Enter path to ECP256 public key PEM file: ")?)?;
            if pubkey.len() != YH_EC_P256_PUBKEY_LEN {
                return Err(MgmError::Error("Invalid public key".to_string()))
            }

            cliclack::note("Creating new authentication key with:",
                           str::replace(&new_authkey.to_string(), "\t", "\n"))?;
            if cliclack::confirm("Create key?").interact()? {
                id = session.import_authentication_publickey(
                    new_authkey.id,
                    &new_authkey.label,
                    &new_authkey.domains,
                    &new_authkey.capabilities,
                    get_delegated_capabilities(new_authkey).as_slice(), &pubkey)?
            }
        }
    };
    cliclack::log::success(format!("Created new authentication key with ID 0x{id:04x}"))?;
    Ok(())
}

fn setup_user(session: &Session, current_authkey: &ObjectDescriptor, user_type: UserType) -> Result<(), MgmError> {
    let new_authkey = match user_type {
        UserType::AsymUser => get_new_object_basics(
            current_authkey, ObjectType::AuthenticationKey,&ASYM_USER_CAPABILITIES, &ASYM_USER_CAPABILITIES)?,
        UserType::AsymAdmin => {
            let mut new_key = get_new_object_basics(
                current_authkey, ObjectType::AuthenticationKey, &ASYM_ADMIN_CAPABILITIES, &[])?;
            let delegated_caps = select_capabilities(
                "Select delegated capabilities", current_authkey, &ASYM_USER_CAPABILITIES, &[])?;
            new_key.delegated_capabilities = if delegated_caps.is_empty() { None } else { Some(delegated_caps) };
            new_key
        },
        UserType::Auditor => get_new_object_basics(
            current_authkey, ObjectType::AuthenticationKey, &AUDITOR_CAPABILITIES, &[ObjectCapability::GetLogEntries])?,
        UserType::BackupAdmin => {
            let current_authkey_delegated = get_delegated_capabilities(current_authkey);
            let mut new_key = get_new_object_basics(
                current_authkey, ObjectType::AuthenticationKey, current_authkey_delegated.as_slice(), current_authkey_delegated.as_slice())?;
            let delegated_caps = select_capabilities(
                "Select delegated capabilities", current_authkey, current_authkey_delegated.as_slice(), current_authkey_delegated.as_slice())?;
            new_key.delegated_capabilities = if delegated_caps.is_empty() { None } else { Some(delegated_caps) };
            new_key
        },
    };
    create_authkey(session, &new_authkey)
}