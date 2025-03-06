use std::collections::HashSet;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{delete_objects, get_domains, get_id, get_label, get_object_properties_str, get_operation_key, get_permissible_capabilities, list_objects, print_object_properties, select_object_capabilities};

const AES_KEY_CAPABILITIES: [ObjectCapability; 5] = [
    ObjectCapability::EncryptCbc,
    ObjectCapability::DecryptCbc,
    ObjectCapability::EncryptEcb,
    ObjectCapability::DecryptEcb,
    ObjectCapability::ExportableUnderWrap];

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum SymCommand {
    #[default]
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
    DeleteKey,
    PerformEncryption,
    PerformDecryption,
    ReturnToMainMenu,
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum AesMode {
    #[default]
    Ecb,
    Cbc,
}

pub fn exec_sym_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_sym_command(session, current_authkey)?;
        let res = match cmd {
            SymCommand::ListKeys => sym_list_keys(session),
            SymCommand::GetKeyProperties => sym_get_key_properties(session),
            SymCommand::GenerateKey => sym_gen_key(session, current_authkey),
            SymCommand::ImportKey => sym_import_key(session, current_authkey),
            SymCommand::DeleteKey => sym_delete_key(session),
            SymCommand::PerformEncryption=> sym_op(session, current_authkey, true),
            SymCommand::PerformDecryption => sym_op(session, current_authkey, false),
            SymCommand::ReturnToMainMenu => return Ok(()),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn get_sym_command(session: &Session, current_authkey: u16) -> Result<SymCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands = cliclack::select("").initial_value(SymCommand::ListKeys);
    commands = commands.item(SymCommand::ListKeys, "List keys", "");
    commands = commands.item(SymCommand::GetKeyProperties, "Get key properties", "");
    if capabilities.contains(&ObjectCapability::GenerateSymmetricKey) {
        commands = commands.item(SymCommand::GenerateKey, "Generate AES key", "");
    }
    if capabilities.contains(&ObjectCapability::PutSymmetricKey) {
        commands = commands.item(SymCommand::ImportKey, "Import AES key", "");
    }
    if capabilities.contains(&ObjectCapability::DeleteSymmetricKey) {
        commands = commands.item(SymCommand::DeleteKey, "Delete AES key", "");
    }
    if HashSet::from([
        ObjectCapability::EncryptEcb,
        ObjectCapability::EncryptCbc]).intersection(&capabilities).count() > 0 {
        commands = commands.item(SymCommand::PerformEncryption, "Do encryption", "");
    }
    if HashSet::from([
        ObjectCapability::DecryptEcb,
        ObjectCapability::DecryptCbc]).intersection(&capabilities).count() > 0 {
        commands = commands.item(SymCommand::PerformDecryption, "Do decryption", "");
    }
    commands = commands.item(SymCommand::ReturnToMainMenu, "Return to main menu", "");
    Ok(commands.interact()?)
}

fn get_all_sym_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let keys = session.
                              list_objects_with_filter(0, ObjectType::SymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    Ok(keys)
}

fn sym_list_keys(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_sym_keys(session)?;

    list_objects(session, &keys)
}

fn sym_get_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_sym_keys(session)?)
}

fn sym_gen_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;



    let key_algorithm = cliclack::select("Choose key algorithm:")
        .item(ObjectAlgorithm::Aes128, "AES128", "")
        .item(ObjectAlgorithm::Aes192, "AES192", "")
        .item(ObjectAlgorithm::Aes256, "AES256", "")
        .interact()?;

    let capabilities = select_object_capabilities(
        "Select key capabilities",
        false,
        true,
        &AES_KEY_CAPABILITIES.to_vec(),
        &permissible_capabilities)?;

    cliclack::note("Generating AES key with:",
                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating AES key...");
        let id = session
            .generate_aes_key(key_id, &label, &capabilities, &*domains, key_algorithm)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated AES key with ID 0x{:04x} on the device", id))?;
    }
    Ok(())
}

fn sym_import_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;

    let capabilities = select_object_capabilities(
        "Select key capabilities",
        false,
        true,
        &AES_KEY_CAPABILITIES.to_vec(),
        &permissible_capabilities)?;

    let key_str:String = cliclack::input("Enter AES key in hex:")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else if input.len() != 32 && input.len() != 48 && input.len() != 64 {
                Err("Input must be 32, 48 or 64 characters long")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let key:Vec<u8> = hex::decode(key_str)?;
    let key_algorithm = match key.len() {
        32 => ObjectAlgorithm::Aes256,
        24 => ObjectAlgorithm::Aes192,
        16 => ObjectAlgorithm::Aes128,
        _ => unreachable!()
    };

    cliclack::note("Import AES key with:",
                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

    if cliclack::confirm("Import key?").interact()? {
        let id = session
            .import_aes_key(key_id, &label, &*domains, &capabilities, key_algorithm, &key)?;
        cliclack::log::success(
            format!("Imported AES key with ID 0x{:04x} on the device", id))?;
    }
    Ok(())
}

fn sym_delete_key(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_sym_keys(session)?)
}

fn sym_op(session: &Session, current_authkey: u16, enc: bool) -> Result<(), MgmError> {

    let mode = cliclack::select("Select encryption mode")
        .item(AesMode::Ecb, "ECB", "")
        .item(AesMode::Cbc, "CBC", "")
        .interact()?;

    let authkey_capabilities = get_permissible_capabilities(session, current_authkey)?;
    let key = match mode {
        AesMode::Ecb => get_operation_key(
            session, &authkey_capabilities,
            [if enc {ObjectCapability::EncryptEcb} else {ObjectCapability::DecryptEcb}].to_vec().as_ref(),
            ObjectType::SymmetricKey,
            &[])?,
        AesMode::Cbc  => get_operation_key(
            session, &authkey_capabilities,
            [if enc {ObjectCapability::EncryptCbc} else {ObjectCapability::DecryptCbc}].to_vec().as_ref(),
            ObjectType::SymmetricKey,
            &[])?,
    };

    let in_data: String = cliclack::input("Enter data in hex or path to file (data must be a multiple of 16 bytes):")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else if input.len() % 32 != 0 {
                Err("Input must be a multiple of 32 characters long")
            } else {
                Ok(())
            }
        }).interact()?;
    let in_data: Vec<u8> = hex::decode(in_data)?;

    let out_data = if enc {
        match mode {
            AesMode::Ecb => session.encrypt_aes_ecb(key.id, &in_data)?,
            AesMode::Cbc => {
                let iv = get_iv()?;
                session.encrypt_aes_cbc(key.id, &iv, &in_data)?
            }
        }
    } else {
        match mode {
            AesMode::Ecb => session.decrypt_aes_ecb(key.id, &in_data)?,
            AesMode::Cbc => {
                let iv = get_iv()?;
                session.decrypt_aes_cbc(key.id, &iv, &in_data)?
            }
        }
    };

    cliclack::log::success(hex::encode(out_data))?;
    Ok(())
}

fn get_iv() -> Result<Vec<u8>, MgmError> {
    let iv: String = cliclack::input("Enter 16 bytes IV in HEX format:")
        .default_input("00000000000000000000000000000000")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else if input.len() != 32 {
                Err("IV must be a 32 characters long")
            } else {
                Ok(())
            }
        }).interact()?;
    Ok(hex::decode(iv)?)
}
