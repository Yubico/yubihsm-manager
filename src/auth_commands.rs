use std::collections::HashSet;

use crate::util::{delete_objects};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{get_common_properties, get_domains, get_id, get_object_properties_str, get_permissible_capabilities, list_objects, print_object_properties, select_object_capabilities};
use wrap_commands::{get_threshold_and_shares, object_to_file, split_wrapkey};

const KSP_WRAPKEY_LEN: usize = 32;

const ALL_USER_CAPABILITIES: [ObjectCapability; 10] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::SignEcdsa,
    ObjectCapability::SignEddsa,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::SignSshCertificate,
    ObjectCapability::SignAttestationCertificate,
    ObjectCapability::ExportableUnderWrap,
];

const ALL_ADMIN_CAPABILITIES: [ObjectCapability; 6] = [
    ObjectCapability::GenerateAsymmetricKey,
    ObjectCapability::PutAsymmetricKey,
    ObjectCapability::DeleteAsymmetricKey,
    ObjectCapability::PutOpaque,
    ObjectCapability::DeleteOpaque,
    ObjectCapability::ExportableUnderWrap,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AuthCommand {
    #[default]
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
        let cmd = get_auth_command(session, current_authkey)?;
        let result = match cmd {
            AuthCommand::ListKeys => auth_list_keys(session),
            AuthCommand::GetKeyProperties => auth_get_key_properties(session),
            AuthCommand::DeleteKey => auth_delete_user(session),
            AuthCommand::SetupUser => auth_setup_user(session, current_authkey),
            AuthCommand::SetupAdmin => auth_setup_admin(session, current_authkey),
            AuthCommand::SetupAuditor => auth_setup_auditor(session, current_authkey),
            AuthCommand::SetupBackupAdmin => auth_setup_backupadmin(session, current_authkey),
            AuthCommand::SetupKsp => setup_ksp(session, current_authkey),
            AuthCommand::Exit => std::process::exit(0),
        };

        result.unwrap_or_else(|err| {
            cliclack::log::error(format!("ERROR! {}", err)).unwrap_or_else(|e| {
                println!("Unable to display error message: {}", e)});
            std::process::exit(1);
        });

    }
}

fn get_auth_command(session: &Session, current_authkey: u16) -> Result<AuthCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .capabilities.into_iter().collect();
    let delegated_capabilities_vec =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities;
    let mut delegated_capabilities: HashSet<ObjectCapability> = HashSet::new();
    if let Some(..) = delegated_capabilities_vec {
        delegated_capabilities = delegated_capabilities_vec.unwrap().into_iter().collect();
    }

    let mut commands = cliclack::select("");
    commands = commands.item(AuthCommand::ListKeys, "List keys", "");
    commands = commands.item(AuthCommand::GetKeyProperties, "Get user info", "");
    if capabilities.contains(&ObjectCapability::DeleteAuthenticationKey) {
        commands = commands.item(AuthCommand::DeleteKey,"Delete user", "");
    }
    if capabilities.contains(&ObjectCapability::PutAuthenticationKey) {

        if HashSet::from(ALL_USER_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands = commands.item(AuthCommand::SetupUser, "Setup user", "Can only use asymmetric keys");
        }
        if HashSet::from(ALL_ADMIN_CAPABILITIES).intersection(&delegated_capabilities).count() > 0 {
            commands = commands.item(AuthCommand::SetupAdmin, "Setup admin", "Can only manage asymmetric keys");
        }
        if delegated_capabilities.contains(&ObjectCapability::GetLogEntries) {
            commands = commands.item(AuthCommand::SetupAuditor, "Setup auditor", "Can only perform audit functions");
        }
        commands = commands.item(AuthCommand::SetupBackupAdmin, "Setup backup user", "Can have all the delegated capabilities of this user");

        if capabilities.contains(&ObjectCapability::PutWrapKey) &&
           HashSet::from(KSP_AUTHKEY_DELEGATED_CAPABILITIES).intersection(&delegated_capabilities).count() > 0  {
            commands = commands.item(AuthCommand::SetupKsp, "Setup KSP user", "");
        }
    }
    commands = commands.item(AuthCommand::Exit, "Exit", "");
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

fn auth_list_keys(session: &Session) -> Result<(), MgmError> {
    list_objects(session, &get_all_auth_keys(session)?)
}

fn auth_get_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_auth_keys(session)?)
}

fn auth_delete_user(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_auth_keys(session)?)
}

fn get_password(prompt: &str) -> Result<String, MgmError> {
    let pwd = cliclack::password(prompt)
        .mask('*')
        .interact()?;

    let pwd_clone = pwd.clone();
    cliclack::password("Re-enter password")
        .mask('*')
        .validate(move |input: &String| {
            if input != &pwd_clone {
                Err("The passwords do not match!")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(pwd)
}

fn create_user(
    session: &Session,
    capabilities: Vec<ObjectCapability>,
    delegated_capabilities: Vec<ObjectCapability>
) -> Result<(), MgmError> {
    let (key_id, label, domains) = get_common_properties();
    let pwd = get_password("Enter user password:")?;

    let mut key_str = get_object_properties_str(
        &ObjectAlgorithm::Aes128YubicoAuthentication, &label, key_id, &domains, &capabilities);
    key_str.push_str("    Delegated capabilities: ");
    delegated_capabilities.iter().for_each(|cap| key_str.push_str(format!("{:?}, ", cap).as_str()));
    key_str.push('\n');

    cliclack::note("Creating authentication key with:", key_str)?;

    if cliclack::confirm("Execute?").interact()? {
        let id = session.import_authentication_key(
            key_id, &label, &domains, &capabilities, &delegated_capabilities, pwd.as_bytes())?;
        cliclack::log::success(format!("Created new authentication key with ID 0x{id:04x}"))?;
    }
    Ok(())
}

fn auth_setup_user(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;

    let selected_capabilities =
        select_object_capabilities(
            "Select key capabilities",
            false,
            true,
            &ALL_USER_CAPABILITIES.to_vec(),
            &permissible_capabilities);
    create_user(session, selected_capabilities, Vec::new())
}

fn auth_setup_admin(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;

    let capabilities =
        select_object_capabilities(
            "Select key capabilities",
            false,
            true,
            &ALL_ADMIN_CAPABILITIES.to_vec(),
            &permissible_capabilities);

    let delegated_capabilities =
        select_object_capabilities(
            "Select key capabilities",
            false,
            true,
            &ALL_USER_CAPABILITIES.to_vec(),
            &permissible_capabilities);

    create_user(session, capabilities, delegated_capabilities)
}

fn auth_setup_auditor(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = session.get_object_info(
        current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
        expect("Cannot read current authentication key's delegated capabilities");

    if !permissible_capabilities.contains(&ObjectCapability::GetLogEntries) {
        cliclack::log::error("Current user does not have permission to create auditor")?;
        return Ok(());
    }

    let mut capabilities = vec![ObjectCapability::GetLogEntries];

    if permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap) &&
        cliclack::confirm("Is key exportable under wrap?").interact()? {
        capabilities.push(ObjectCapability::ExportableUnderWrap);
    }

    create_user(session, capabilities, Vec::new())
}

fn auth_setup_backupadmin(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let permissible_capabilities = session.get_object_info(
        current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities.
        expect("Cannot read current authentication key's delegated capabilities");

    let mut capabilities = cliclack::multiselect(
        "Select key capabilities. Press the space button to select and unselect item. Press 'Enter' when done.");
    capabilities = capabilities.required(false);
    capabilities = capabilities.initial_values(permissible_capabilities.clone());
    for c in &permissible_capabilities {
        capabilities = capabilities.item(c.clone(), c.to_string(), "");
    }
    let capabilities = capabilities.interact()?;

    let mut delegated_capabilities = cliclack::multiselect(
        "Select key capabilities. Press the space button to select and unselect item. Press 'Enter' when done.");
    delegated_capabilities = delegated_capabilities.required(false);
    delegated_capabilities = delegated_capabilities.initial_values(permissible_capabilities.clone());
    for c in &permissible_capabilities {
        delegated_capabilities = delegated_capabilities.item(c.clone(), c.to_string(), "");
    }
    let delegated_capabilities = delegated_capabilities.interact()?;

    create_user(session, capabilities, delegated_capabilities)
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

    if cliclack::confirm("Would you like to add RSA decryption capabilities?").interact()? {
        wrapkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
        authkey_capabilities.extend_from_slice(capabilities_rsa_decrypt);
        authkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
    }

    let &wrapkey_capabilities = &[
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
    ];

    let wrapkey = session.get_random(KSP_WRAPKEY_LEN)?;

    let domains = get_domains();

    // Create a wrapping key for importing application authentication keys and secrets
    let wrap_id = get_id("Enter wrap key ID [Default 0 for device generated ID]:", "0");
    let wrap_id = session
        .import_wrap_key(
            wrap_id,
            "KSP Wrap key",
            &domains,
            &wrapkey_capabilities,
            ObjectAlgorithm::Aes256CcmWrap,
            &wrapkey_delegated,
            &wrapkey,
        )?;
    cliclack::log::success(format!("Stored wrap key with ID 0x{:04x} on the device\n", wrap_id))?;

    // Split the wrap key
    let (threshold, shares) = get_threshold_and_shares()?;
    split_wrapkey(
        wrap_id,
        &domains,
        &wrapkey_capabilities,
        &wrapkey_delegated,
        &wrapkey,
        threshold,
        shares,
    )?;

    // Create an authentication key for usage with the above wrap key
    let auth_id = get_id("Enter application authentication key ID [Default 0 for device generated ID]:", "0");
    let application_password = get_password("Enter application authentication key password:")?;

    let auth_id = session
        .import_authentication_key(
            auth_id,
            "Application auth key",
            &domains,
            &authkey_capabilities,
            &authkey_delegated,
            application_password.as_bytes(),
        )?;
    cliclack::log::success(format!(
        "Stored application authentication key with ID 0x{:04x} on the device",
        auth_id
    ))?;

    let mut export = false;
    if cliclack::confirm("Export Authentication key? ").interact()? {
        export = true;
        let auth_wrapped = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, auth_id)?;

        let auth_file = object_to_file(auth_id, ObjectType::AuthenticationKey, &auth_wrapped)?;

        cliclack::log::success(format!(
            "Saved wrapped application authentication key to {}\n",
            auth_file
        ))?;
    }

    if cliclack::confirm("Would you like to create an audit key?").interact()? {
        add_audit_key(session, wrap_id, &domains, export)?;
    }

    if cliclack::confirm("Delete previous authentication key (strongly recommended)?").interact()? {
        session.delete_object(current_authkey, ObjectType::AuthenticationKey)?;
    }

    Ok(())
}

fn add_audit_key(
    session: &Session,
    wrap_id: u16,
    domains: &[ObjectDomain],
    export: bool,
) -> Result<(), MgmError> {
    let audit_id = get_id("Enter audit key ID (0 to choose automatically):", "0");
    let audit_password = get_password("Enter audit authentication key password:")?;

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
    cliclack::log::success(format!(
        "Stored audit authentication key with ID 0x{:04x} on the device",
        audit_id
    ))?;

    if export {
        let audit_wrapped = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, audit_id)?;

        let audit_file =
            object_to_file(audit_id, ObjectType::AuthenticationKey, &audit_wrapped)?;
        cliclack::log::success(format!("Saved wrapped audit authentication key to {}\n", audit_file))?;
    }

    Ok(())
}
