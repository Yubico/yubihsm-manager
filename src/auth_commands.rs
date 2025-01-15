use std::collections::HashSet;

use crate::util::{delete_objects};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{get_domains, get_ec_pubkey_from_pemfile, get_file_path, get_id, get_label, get_object_properties_str, get_permissible_capabilities, InputOutputFormat, list_objects, print_object_properties, read_file_bytes, select_object_capabilities};
use wrap_commands::{get_shares, get_threshold, object_to_file, split_wrapkey};
use YH_EC_P256_PUBKEY_LEN;

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
    ReturnToMainMenu,
}

pub fn exec_auth_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_auth_command(session, current_authkey)?;
        let res = match cmd {
            AuthCommand::ListKeys => auth_list_keys(session),
            AuthCommand::GetKeyProperties => auth_get_key_properties(session),
            AuthCommand::DeleteKey => auth_delete_user(session),
            AuthCommand::SetupUser => auth_setup_user(session, current_authkey),
            AuthCommand::SetupAdmin => auth_setup_admin(session, current_authkey),
            AuthCommand::SetupAuditor => auth_setup_auditor(session, current_authkey),
            AuthCommand::SetupBackupAdmin => auth_setup_backupadmin(session, current_authkey),
            AuthCommand::SetupKsp => setup_ksp(session, current_authkey),
            AuthCommand::ReturnToMainMenu => return Ok(()),
        };

        if let Err(err) = res {
            cliclack::log::error(err)?;
        }
    }
}

fn get_auth_command(session: &Session, current_authkey: u16) -> Result<AuthCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .capabilities.into_iter().collect();
    let Some(delegated_capabilities_vec) =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities
        else {
            return Err(MgmError::Error("Failed to read current authkey delegated capabilities".to_string()))
        };
    let delegated_capabilities:HashSet<ObjectCapability> = delegated_capabilities_vec.into_iter().collect();

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
    commands = commands.item(AuthCommand::ReturnToMainMenu, "Return to main menu", "");
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
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let mut key_str = get_object_properties_str(
        &ObjectAlgorithm::Aes128YubicoAuthentication, &label, key_id, &domains, &capabilities);
    key_str.push_str("    Delegated capabilities: ");
    delegated_capabilities.iter().for_each(|cap| key_str.push_str(format!("{:?}, ", cap).as_str()));
    key_str.push('\n');

    cliclack::note("Creating authentication key with:", key_str)?;
    if !cliclack::confirm("Create authentication key?").interact()? {
        return Ok(())
    }

    let asymauth = cliclack::select("Select authentication key type:")
        .item(false, "Password derived", "Session keys are derived from a password")
        .item(true, "Asymmetric", "Using ECP256 curve")
        .interact()?;

    if !asymauth {
        let pwd = get_password("Enter user password:")?;

        let id = session.import_authentication_key(
            key_id, &label, &domains, &capabilities, &delegated_capabilities, pwd.as_bytes())?;
        cliclack::log::success(format!("Created new authentication key with ID 0x{id:04x}"))?;

    } else {
        let format = cliclack::select("Select public key format:")
            .initial_value(InputOutputFormat::PEM)
            .item(InputOutputFormat::PEM, InputOutputFormat::PEM, "")
            .item(InputOutputFormat::BINARY, InputOutputFormat::BINARY, "")
            .interact()?;

        let pubkey = match format {
            InputOutputFormat::PEM => {
                get_ec_pubkey_from_pemfile(get_file_path("Enter path to ECP256 public key PEM file: ")?)?
            }
            InputOutputFormat::BINARY => {
                read_file_bytes("Enter path to ECP256 public key binary file: ")?
            }
            _ => unreachable!()
        };

        if pubkey.len() != YH_EC_P256_PUBKEY_LEN {
            return Err(MgmError::Error("Invalid public key".to_string()))
        }
        let id = session.import_authentication_publickey(
            key_id, &label, &domains, &capabilities, &delegated_capabilities, &pubkey)?;
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
            &permissible_capabilities)?;
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
            &permissible_capabilities)?;

    let delegated_capabilities =
        select_object_capabilities(
            "Select key capabilities",
            false,
            true,
            &ALL_USER_CAPABILITIES.to_vec(),
            &permissible_capabilities)?;

    create_user(session, capabilities, delegated_capabilities)
}

fn auth_setup_auditor(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let Some(permissible_capabilities) = session.get_object_info(
        current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities else {
        return Err(MgmError::Error("Cannot read current authentication key's delegated capabilities".to_string()))
    };

    if !permissible_capabilities.contains(&ObjectCapability::GetLogEntries) {
        return Err(MgmError::Error("Current user does not have permission to create auditor".to_string()));
    }

    let mut capabilities = vec![ObjectCapability::GetLogEntries];

    if permissible_capabilities.contains(&ObjectCapability::ExportableUnderWrap) &&
        cliclack::confirm("Is key exportable under wrap?").interact()? {
        capabilities.push(ObjectCapability::ExportableUnderWrap);
    }

    create_user(session, capabilities, Vec::new())
}

fn auth_setup_backupadmin(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let Some(permissible_capabilities) = session.get_object_info(
        current_authkey, ObjectType::AuthenticationKey)?.delegated_capabilities else {
        return Err(MgmError::Error("Cannot read current authentication key's delegated capabilities".to_string()))
    };

    let capabilities = select_object_capabilities(
        "Select key capabilities",
        true,
        false,
        &permissible_capabilities,
        &permissible_capabilities)?;

    let delegated_capabilities = select_object_capabilities(
        "Select key delegated capabilities",
        true,
        false,
        &permissible_capabilities,
        &permissible_capabilities)?;

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

    if cliclack::confirm("Add RSA decryption capabilities?").interact()? {
        wrapkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
        authkey_capabilities.extend_from_slice(capabilities_rsa_decrypt);
        authkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
    }

    let &wrapkey_capabilities = &[
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
    ];

    let wrapkey = session.get_random(KSP_WRAPKEY_LEN)?;

    let domains = get_domains()?;

    // Create a wrapping key for importing application authentication keys and secrets
    let wrap_id = get_id()?;
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
    let shares = get_shares()?;
    let threshold = get_threshold(shares)?;
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
    let auth_id = get_id()?;
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

    if cliclack::confirm("Create an audit key?").interact()? {
        add_ksp_audit_key(session, wrap_id, &domains, export)?;
    }

    if cliclack::confirm("Delete the current authentication key (strongly recommended)?").interact()? {
        session.delete_object(current_authkey, ObjectType::AuthenticationKey)?;
    }

    Ok(())
}

fn add_ksp_audit_key(
    session: &Session,
    wrap_id: u16,
    domains: &[ObjectDomain],
    export: bool,
) -> Result<(), MgmError> {
    let audit_id = get_id()?;
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
        cliclack::log::success(format!("Saved wrapped audit authentication key to {}", audit_file))?;
    }

    Ok(())
}
