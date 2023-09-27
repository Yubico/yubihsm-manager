use std::collections::HashSet;
use std::io::{stdout, Write};
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDescriptor, get_common_properties, get_domains, get_filtered_objects, get_integer_or_default, get_selection_items_from_vec, print_object_properties, select_object_capabilities};
use wrap_commands::{get_threshold_and_shares, object_to_file, split_wrapkey};

const KSP_WRAPKEY_LEN: usize = 32;

const ALL_USER_CAPABILITIES: [ObjectCapability; 9] = [
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

const ALL_ADMIN_CAPABILITIES: [ObjectCapability; 5] = [
    ObjectCapability::GenerateAsymmetricKey,
    ObjectCapability::PutAsymmetricKey,
    ObjectCapability::DeleteAsymmetricKey,
    ObjectCapability::PutOpaque,
    ObjectCapability::DeleteOpaque,
];

const KSP_AUTHKEY_DELEGATED_CAPABILITIES: [ObjectCapability; 11] = [
    ObjectCapability::GenerateAsymmetricKey,
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::SignEcdsa,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::ExportWrapped,
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportWrapped,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::GetLogEntries,
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
    SetupKsp,
    Exit,
}

pub fn exec_auth_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        println!();
        let cmd = get_auth_command(session, current_authkey)?;
        match cmd {
            AuthCommand::ListKeys => auth_list_keys(session)?,
            AuthCommand::GetKeyProperties => auth_get_key_properties(session)?,
            AuthCommand::DeleteKey => auth_delete_user(session)?,
            AuthCommand::SetupUser => auth_setup_user(session, current_authkey)?,
            AuthCommand::SetupAdmin => auth_setup_admin(session, current_authkey)?,
            AuthCommand::SetupAuditor => auth_setup_auditor(session, current_authkey)?,
            AuthCommand::SetupBackupAdmin => auth_setup_backupadmin(session, current_authkey)?,
            AuthCommand::SetupKsp => setup_ksp(session, current_authkey)?,
            AuthCommand::Exit => std::process::exit(0),
        }
    }
}

fn get_auth_command(session: &Session, current_authkey: u16) -> Result<AuthCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();
    let delegated_capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.unwrap().into_iter().collect();


    let mut commands: Vec<(String, AuthCommand)> = Vec::new();
    commands.push(("List keys".to_string(), AuthCommand::ListKeys));
    commands.push(("Get user info".to_string(), AuthCommand::GetKeyProperties));
    if capabilities.contains(&ObjectCapability::DeleteAuthenticationKey) {
        commands.push(("Delete user".to_string(), AuthCommand::DeleteKey));
    }
    if capabilities.contains(&ObjectCapability::PutAuthenticationKey) {

        if HashSet::from(ALL_USER_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands.push(("Setup user: Can only use keys".to_string(), AuthCommand::SetupUser));
        }
        if HashSet::from(ALL_ADMIN_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands.push(("Setup admin: Can create keys".to_string(), AuthCommand::SetupAdmin));
        }
        if delegated_capabilities.contains(&ObjectCapability::GetLogEntries) {
            commands.push(("Setup auditor: Can only perform audit functions".to_string(), AuthCommand::SetupAuditor));
        }
        commands.push(("Setup backup user: Can have all the delegated capabilities of this user".to_string(), AuthCommand::SetupBackupAdmin));

        if capabilities.contains(&ObjectCapability::PutWrapKey) &&
           HashSet::from(KSP_AUTHKEY_DELEGATED_CAPABILITIES).intersection(&delegated_capabilities).count() > 0  {
            commands.push(("Setup KSP user".to_string(), AuthCommand::SetupKsp));
        }
    }
    commands.push(("Exit".to_string(), AuthCommand::Exit));

    Ok(get_menu_option(&commands))
}

fn auth_list_keys(session: &Session) -> Result<(), MgmError> {
    let key_handles: Vec<ObjectHandle> = session.list_objects_with_filter(0, ObjectType::AuthenticationKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    println!("\nFound {} objects", key_handles.len());
    for object in key_handles {
        println!("  {}", BasicDescriptor::from(session.get_object_info(object.object_id, object.object_type)?));
    }
    Ok(())
}

fn auth_get_key_properties(session: &Session) -> Result<(), MgmError> {
    println!();
    print_object_properties(session, ObjectType::AuthenticationKey);
    Ok(())
}

fn auth_delete_user(session: &Session) -> Result<(), MgmError> {
    let keys = get_filtered_objects(session, ObjectType::AuthenticationKey, false)?;
    delete_objects(session, keys)
}

fn create_user(
    session: &Session,
    mut capabilities: Vec<ObjectCapability>,
    delegated_capabilities: Vec<ObjectCapability>,
    exportable: bool,
) -> Result<(), MgmError> {
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
        let id = session.import_authentication_key(key_id, &label, &domains, &capabilities, &delegated_capabilities, derivation_pwd.as_bytes())?;
        println!("Created new authentication key with ID 0x{id:04x}");
    }
    Ok(())
}

fn auth_setup_user(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities.unwrap().into_iter().collect();

    let selected_capabilities =
        select_object_capabilities(&HashSet::from(ALL_USER_CAPABILITIES), &permissible_capabilities);
    create_user(session, selected_capabilities, Vec::new(), permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))
}

fn auth_setup_admin(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities.expect("Cannot read current authentication key's delegated capabilities")
            .into_iter().collect();

    print!("\nChoose admin user capabilities. ");
    let selected_capabilities =
        select_object_capabilities(&HashSet::from(ALL_ADMIN_CAPABILITIES), &permissible_capabilities);

    print!("\nChoose admin user delegated capabilities. ");
    let mut delegated_caps: Vec<ObjectCapability> = Vec::new();
    ALL_USER_CAPABILITIES.map(|c| delegated_caps.push(c));
    delegated_caps.push(ObjectCapability::ExportableUnderWrap);
    let selected_delegated_capabilities =
        select_object_capabilities(&delegated_caps.into_iter().collect(), &permissible_capabilities);

    create_user(session, selected_capabilities, selected_delegated_capabilities, permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))
}

fn auth_setup_auditor(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = session.get_object_info(
        current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
        expect("Cannot read current authentication key's delegated capabilities");

    if !permissible_capabilities.contains(&ObjectCapability::GetLogEntries) {
        return Err(MgmError::Error("Current user does not have permission to create auditor".to_string()));
    }

    let capabilities = vec![ObjectCapability::GetLogEntries];

    create_user(session, capabilities, Vec::new(), permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap))
}

fn auth_setup_backupadmin(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = session.get_object_info(
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
    println!();

    let mut delegated_capabilities = permissible_capabilities.clone();
    if !bool::from(get_boolean_answer("Use all current user delegated capabilities as new user delegated capabilities? ")) {
        delegated_capabilities = get_selected_items(&mut get_selection_items_from_vec(&permissible_capabilities));
    }
    println!();

    // exportable_underwrap does not need to be added explicitly because it should already be there
    create_user(session, capabilities, delegated_capabilities, false)
}


fn setup_ksp(session: &Session, current_authkey: u16) -> Result<(), MgmError>{
    let capabilities_rsa_decrypt = &[ObjectCapability::DecryptPkcs, ObjectCapability::DecryptOaep];

    let mut wrapkey_delegated = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetLogEntries,
    ];

    let mut authkey_capabilities = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
    ];

    let mut authkey_delegated = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ExportableUnderWrap,
    ];

    if Into::<bool>::into(get_boolean_answer(
        "Would you like to add RSA decryption capabilities?",
    )) {
        wrapkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
        authkey_capabilities.extend_from_slice(capabilities_rsa_decrypt);
        authkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
    }

    let &wrapkey_capabilities = &[
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
    ];

    let wrapkey = session.get_random(KSP_WRAPKEY_LEN).unwrap_or_else(|err| {
        println!("Unable to generate random data: {}", err);
        std::process::exit(1);
    });

    let domains = get_domains("Enter domains:");

    // Create a wrapping key for importing application authentication keys and secrets
    let wrap_id = get_integer_or_default("Enter wrap key ID (0 to choose automatically):", 0);
    let wrap_id = session
        .import_wrap_key(
            wrap_id,
            "Wrap key",
            &domains,
            &wrapkey_capabilities,
            ObjectAlgorithm::Aes256CcmWrap,
            &wrapkey_delegated,
            &wrapkey,
        )?;
    println!("Stored wrap key with ID 0x{:04x} on the device\n", wrap_id);

    // Split the wrap key
    let (threshold, shares) = get_threshold_and_shares();
    split_wrapkey(
        wrap_id,
        &domains,
        &wrapkey_capabilities,
        &wrapkey_delegated,
        &wrapkey,
        threshold,
        shares,
    );

    // Create an authentication key for usage with the above wrap key
    let auth_id = get_integer_or_default(
        "Enter application authentication key ID (0 to choose automatically):",
        0);
    let application_password = get_string("Enter application authentication key password:");
    let auth_id = session
        .import_authentication_key(
            auth_id,
            "Application auth key",
            &domains,
            &authkey_capabilities,
            &authkey_delegated,
            application_password.as_bytes(),
        )?;
    println!(
        "Stored application authentication key with ID 0x{:04x} on the device",
        auth_id
    );

    let mut export = false;
    if bool::from(get_boolean_answer("Export Authentication key? ")) {
        export = true;
        let auth_wrapped = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, auth_id)?;

        let auth_file = object_to_file(auth_id, ObjectType::AuthenticationKey, &auth_wrapped)?;

        println!(
            "Saved wrapped application authentication key to {}\n",
            auth_file
        );
    }

    if bool::from(get_boolean_answer("Would you like to create an audit key?")) {
        add_audit_key(session, wrap_id, &domains, export)?;
    }

    if bool::from(get_boolean_answer("Delete previous authentication key (strongly recommended)?")) {
        delete_objects(session, vec![ObjectHandle{object_type:ObjectType::AuthenticationKey, object_id:current_authkey}].to_vec())?;
    }

    Ok(())
}

fn add_audit_key(
    session: &Session,
    wrap_id: u16,
    domains: &[ObjectDomain],
    export: bool,
) -> Result<(), MgmError> {
    let audit_id = get_integer_or_default("Enter audit key ID (0 to choose automatically):", 0);
    let audit_password = get_string("Enter audit authentication key password:");

    // Create audit auth key
    let audit_id = session
        .import_authentication_key(
            audit_id,
            "Audit auth key",
            domains,
            &[
                ObjectCapability::GetLogEntries,
                ObjectCapability::ExportableUnderWrap,
            ],
            &[],
            audit_password.as_bytes(),
        )?;
    println!(
        "Stored audit authentication key with ID 0x{:04x} on the device",
        audit_id
    );

    if export {
        let audit_wrapped = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, audit_id)?;

        let audit_file =
            object_to_file(audit_id, ObjectType::AuthenticationKey, &audit_wrapped)?;
        println!("Saved wrapped audit authentication key to {}\n", audit_file);
    }

    Ok(())
}
