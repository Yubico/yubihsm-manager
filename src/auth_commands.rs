use std::io::{stdout, Write};
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDiscriptor, get_common_properties, get_filtered_objects, get_integer_or_default, get_intersection, get_selection_items_from_vec, get_string_or_default, MultiSelectItem, print_object_properties, read_file_bytes, write_file};

const ALL_USER_CAPABILITIES:[ObjectCapability;9] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::SignEcdsa,
    ObjectCapability::SignEddsa,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::SignSshCertificate,
    ObjectCapability::SignAttestationCertificate,
];

const ALL_ADMIN_CAPABILITIES:[ObjectCapability;5] = [
    ObjectCapability::GenerateAsymmetricKey,
    ObjectCapability::PutAsymmetricKey,
    ObjectCapability::DeleteAsymmetricKey,
    ObjectCapability::PutOpaque,
    ObjectCapability::DeleteOpaque,
];

#[derive(Debug, Clone, Copy)]
enum AuthCommands {
    ListKeys,
    GetKeyProperties,
    DeleteKey,
    SetupUser,
    SetupAdmin,
    SetupAuditor,
    SetupBackupAdmin,
    Exit,
}

pub fn exec_auth_command(session: Option<&Session>, current_authkey:u16) -> Result<(), MgmError> {
    stdout().flush().unwrap();
    let cmd = get_auth_command();
    match cmd {
        AuthCommands::ListKeys => auth_list_keys(session),
        AuthCommands::GetKeyProperties => auth_get_key_properties(session),
        AuthCommands::DeleteKey => auth_delete_user(session),
        AuthCommands::SetupUser => auth_setup_user(session, current_authkey),
        AuthCommands::Exit => std::process::exit(0),
        _ => unreachable!()
    }
}

fn get_auth_command() -> AuthCommands {
    println!();
    let commands: [(String, AuthCommands);8] = [
        ("List keys".to_string(), AuthCommands::ListKeys),
        ("Get user info".to_string(), AuthCommands::GetKeyProperties),
        ("Delete user".to_string(), AuthCommands::DeleteKey),
        ("Setup user: Can only use keys".to_string(), AuthCommands::SetupUser),
        ("Setup admin: Can create keys".to_string(), AuthCommands::SetupAdmin),
        ("Setup auditor: Can only perform audit functions".to_string(), AuthCommands::SetupAuditor),
        ("Setup backup user: Can do all the above, create new users and perform backup and restore operations".to_string(), AuthCommands::SetupBackupAdmin),
        ("Exit".to_string(), AuthCommands::Exit)];
    get_menu_option(&commands.to_vec())
}

fn auth_list_keys(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("\n  > yubihsm-shell -a list-objects -t authentication-key"),
        Some(s) => {
            let key_handles:Vec<ObjectHandle> = s.list_objects_with_filter(0, ObjectType::AuthenticationKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
            println!("Found {} objects", key_handles.len());
            for object in key_handles {
                println!("  {}", BasicDiscriptor::from(s.get_object_info(object.object_id, object.object_type)?));
            }
        }
    }
    Ok(())
}

fn auth_get_key_properties(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("No session available"),
        Some(s) => {
            println!();
            print_object_properties(s, ObjectType::AuthenticationKey);
        }
    }
    Ok(())
}

fn auth_delete_user(session: Option<&Session>) -> Result<(), MgmError>{
    match session {
        None => println!("No session available"),
        Some(s) => {
            let keys = get_filtered_objects(s, ObjectType::AuthenticationKey, false)?;
            delete_objects(session, keys)?
        }
    }
    Ok(())
}

fn auth_setup_user(session:Option<&Session>, current_authkey:u16) -> Result<(), MgmError>{
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let (mut key_id, label, domains) = get_common_properties();
            let derivation_pwd = get_string("Enter user password: ");
            let exportable = bool::from(get_boolean_answer("Should key be exportable under wrap? "));
            let delegated_capabilities = s.get_object_info(
                current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
                expect("Cannot read object delegated capabilities");
            let mut capabilities_options = get_selection_items_from_vec(get_intersection(ALL_USER_CAPABILITIES.to_vec(), delegated_capabilities));
            let mut selected_capabilities = get_selected_items(&mut capabilities_options);
            if exportable {
                selected_capabilities.push(ObjectCapability::ExportableUnderWrap);
            }

            println!("\n  Creating authentication key with:");
            println!("    Label: {}", label);
            println!("    Key ID: {}", key_id);
            print!("    Domains: ");
            domains.iter().for_each(|domain| print!("{}, ", domain));
            println!();
            print!("    Capabilities: ");
            selected_capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
            println!();
            println!("    Delegated capabilities: None");
            println!();

            if bool::from(get_boolean_answer("Execute? ")) {
                s.import_authentication_key(key_id, &label, &*domains, &selected_capabilities, &Vec::new(), derivation_pwd.as_bytes())?;
                println!("Created new authentication key with ID 0x{key_id:04x}");
            }
        }
    }
    Ok(())
}

