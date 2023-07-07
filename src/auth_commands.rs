use std::collections::HashSet;
use std::io::{stdout, Write};
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDiscriptor, get_common_properties, get_filtered_objects, get_integer_or_default, get_selection_items_from_vec, get_string_or_default, MultiSelectItem, print_object_properties, read_file_bytes, select_object_capabilities, write_file};

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
enum AuthCommand {
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
    let cmd = get_auth_command(session.unwrap(), current_authkey)?;
    match cmd {
        AuthCommand::ListKeys => auth_list_keys(session),
        AuthCommand::GetKeyProperties => auth_get_key_properties(session),
        AuthCommand::DeleteKey => auth_delete_user(session),
        AuthCommand::SetupUser => auth_setup_user(session, current_authkey),
        AuthCommand::SetupAdmin => auth_setup_admin(session, current_authkey),
        AuthCommand::SetupAuditor => auth_setup_auditor(session, current_authkey),
        AuthCommand::SetupBackupAdmin => auth_setup_backupadmin(session,current_authkey),
        AuthCommand::Exit => std::process::exit(0),
        _ => unreachable!()
    }
}

fn get_auth_command(session:&Session, current_authkey:u16) -> Result<AuthCommand, MgmError> {

    let capabilities:HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();
    let delegated_capabilities:HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.unwrap().into_iter().collect();


    let mut commands:Vec<(String, AuthCommand)> = Vec::new();
    commands.push(("List keys".to_string(), AuthCommand::ListKeys));
    commands.push(("Get user info".to_string(), AuthCommand::GetKeyProperties));
    if capabilities.contains(&ObjectCapability::DeleteAuthenticationKey) {
        commands.push(("Delete user".to_string(), AuthCommand::DeleteKey));

        if HashSet::from(ALL_USER_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands.push(("Setup user: Can only use keys".to_string(), AuthCommand::SetupUser));
        }
        if HashSet::from(ALL_ADMIN_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands.push(("Setup admin: Can create keys".to_string(), AuthCommand::SetupAdmin));
        }
        if delegated_capabilities.contains(&ObjectCapability::GetLogEntries) {
            commands.push(("Setup auditor: Can only perform audit functions".to_string(), AuthCommand::SetupAuditor));
        }
        commands.push(("Setup backup user: Can have all the delegated capabilities of this user".to_string(), AuthCommand::SetupBackupAdmin))
    }
    commands.push(("Exit".to_string(), AuthCommand::Exit));

    Ok(get_menu_option(&commands))
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

fn create_user(
    session:&Session,
    mut capabilities:Vec<ObjectCapability>,
    delegated_capabilities:Vec<ObjectCapability>,
    exportable:bool,
) -> Result<(), MgmError>{
    println!();
    let (key_id, label, domains) = get_common_properties();
    let derivation_pwd = get_string("Enter user password: ");
    if exportable &&
        bool::from(get_boolean_answer("Should key be exportable under wrap? ")) {
        capabilities.push(ObjectCapability::ExportableUnderWrap);
    }

    println!("\n  Creating authentication key with:");
    println!("    Label: {}", label);
    println!("    Key ID: {}", key_id);
    print!("    Domains: ");
    domains.iter().for_each(|domain| print!("{}, ", domain));
    println!();
    print!("    Capabilities: ");
    capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!();
    print!("    Delegated capabilities: ");
    delegated_capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!();

    if bool::from(get_boolean_answer("Execute? ")) {
        let id = session.import_authentication_key(key_id, &label, &*domains, &capabilities, &delegated_capabilities, derivation_pwd.as_bytes())?;
        println!("Created new authentication key with ID 0x{id:04x}");
    }
    Ok(())
}

fn auth_setup_user(session:Option<&Session>, current_authkey:u16) -> Result<(), MgmError>{
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let permissible_capabilities:HashSet<ObjectCapability> =
                session.unwrap().get_object_info(current_authkey, ObjectType::AuthenticationKey)?
                    .delegated_capabilities.unwrap().into_iter().collect();

            let selected_capabilities =
                select_object_capabilities(&HashSet::from(ALL_USER_CAPABILITIES), &permissible_capabilities);
            create_user(s, selected_capabilities, Vec::new(), permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))?
        }
    }
    Ok(())
}

fn auth_setup_admin(session:Option<&Session>, current_authkey:u16) -> Result<(), MgmError>{
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let permissible_capabilities:HashSet<ObjectCapability> =
                session.unwrap().get_object_info(current_authkey, ObjectType::AuthenticationKey)?
                    .delegated_capabilities.expect("Cannot read current authentication key's delegated capabilities")
                    .into_iter().collect();

            print!("\nChoose admin user capabilities. ");
            let selected_capabilities =
                select_object_capabilities(&HashSet::from(ALL_ADMIN_CAPABILITIES), &permissible_capabilities);

            print!("\nChoose admin user delegated capabilities. ");
            let mut delegated_caps:Vec<ObjectCapability> = Vec::new();
            ALL_USER_CAPABILITIES.map(|c| delegated_caps.push(c));
            delegated_caps.push(ObjectCapability::ExportableUnderWrap);
            let selected_delegated_capabilities =
                select_object_capabilities(&delegated_caps.into_iter().collect(), &permissible_capabilities);

            create_user(s, selected_capabilities, selected_delegated_capabilities, permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))?
        }
    }
    Ok(())
}

fn auth_setup_auditor(session:Option<&Session>, current_authkey:u16) -> Result<(), MgmError>{
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let permissible_capabilities = s.get_object_info(
                current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
                expect("Cannot read current authentication key's delegated capabilities");

            if !permissible_capabilities.contains(&ObjectCapability::GetLogEntries) {
                return Err(MgmError::Error("Current user does not have permission to create auditor".to_string()));
            }

            let capabilities = vec![ObjectCapability::GetLogEntries];

            create_user(s, capabilities, Vec::new(), permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))?
        }
    }
    Ok(())
}

fn auth_setup_backupadmin(session:Option<&Session>, current_authkey:u16) -> Result<(), MgmError>{
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let permissible_capabilities = s.get_object_info(
                current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
                expect("Cannot read current authentication key's delegated capabilities");

            println!("\n  Current user delegated capabilities:");
            for c in &permissible_capabilities {
                println!("  {c}");
            }
            println!();

            let mut capabilities = permissible_capabilities.clone();
            if !bool::from(get_boolean_answer("Use all current user delegated capabilities as new user capabilities? ")) {
                capabilities = get_selected_items(&mut get_selection_items_from_vec(&permissible_capabilities));
            }
            println!("");

            let mut delegated_capabilities = permissible_capabilities.clone();
            if !bool::from(get_boolean_answer("Use all current user delegated capabilities as new user delegated capabilities? ")) {
                delegated_capabilities = get_selected_items(&mut get_selection_items_from_vec(&permissible_capabilities));
            }
            println!("");

            // exportable_underwrap does not need to be added explicitly because it should already be there
            create_user(s, capabilities, delegated_capabilities, false)?
        }
    }
    Ok(())
}

