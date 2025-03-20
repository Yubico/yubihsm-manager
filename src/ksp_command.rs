use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{get_directory, get_domains, get_id, get_password};
use wrap_commands::{get_shares, get_threshold, object_to_file, split_wrapkey};

const KSP_WRAPKEY_LEN: usize = 32;

pub fn setup_ksp(session: &Session, current_authkey: u16) -> Result<(), MgmError>{
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
        ObjectCapability::GetOption,
    ];

    let mut authkey_delegated = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetOption,
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

        let auth_file = object_to_file(
            get_directory("Enter destination directory:")?, auth_id, ObjectType::AuthenticationKey, &auth_wrapped)?;

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
            object_to_file(
                get_directory("Enter destination directory:")?, audit_id, ObjectType::AuthenticationKey, &audit_wrapped)?;
        cliclack::log::success(format!("Saved wrapped audit authentication key to {}", audit_file))?;
    }

    Ok(())
}
