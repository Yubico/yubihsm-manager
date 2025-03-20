use std::fmt;
use std::fmt::Display;
use std::sync::LazyLock;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use MAIN_STRING;
use util::{delete_objects, get_new_object_basics, get_op_key, list_objects, print_object_properties};

static SYM_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Symmetric keys", MAIN_STRING));

const AES_KEY_CAPABILITIES: [ObjectCapability; 5] = [
    ObjectCapability::EncryptCbc,
    ObjectCapability::DecryptCbc,
    ObjectCapability::EncryptEcb,
    ObjectCapability::DecryptEcb,
    ObjectCapability::ExportableUnderWrap];

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum SymCommand {
    #[default]
    List,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    Encrypt,
    Decrypt,
    ReturnToMainMenu,
    Exit,
}

impl Display for SymCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SymCommand::List => write!(f, "List"),
            SymCommand::GetKeyProperties => write!(f, "Print object properties"),
            SymCommand::Generate => write!(f, "Generate"),
            SymCommand::Import => write!(f, "Import"),
            SymCommand::Delete => write!(f, "Delete"),
            SymCommand::Encrypt => write!(f, "Encrypt"),
            SymCommand::Decrypt => write!(f, "Decrypt"),
            SymCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            SymCommand::Exit => write!(f, "Exit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum AesMode {
    #[default]
    Ecb,
    Cbc,
}

pub fn exec_sym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {
        println!("\n{}", SYM_STRING.to_string());

        let cmd = get_command(authkey)?;
        let res = match cmd {
            SymCommand::List => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::List);
                list(session)
            },
            SymCommand::GetKeyProperties => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::GetKeyProperties);
                print_key_properties(session)
            },
            SymCommand::Generate => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::Generate);
                generate(session, authkey)
            },
            SymCommand::Import => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::Import);
                import(session, authkey)
            },
            SymCommand::Delete => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::Delete);
                delete(session)
            },
            SymCommand::Encrypt => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::Encrypt);
                operate(session, authkey, true)
            },
            SymCommand::Decrypt => {
                println!("\n{} > {}\n", SYM_STRING.to_string(), SymCommand::Decrypt);
                operate(session, authkey, false)
            },
            SymCommand::ReturnToMainMenu => return Ok(()),
            SymCommand::Exit => std::process::exit(0),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn get_command(authkey: &ObjectDescriptor) -> Result<SymCommand, MgmError> {
    // let capabilities: HashSet<ObjectCapability> = authkey.capabilities.into_iter().collect();
    let capabilities= &authkey.capabilities;

    let mut commands = cliclack::select("").initial_value(SymCommand::List);
    commands = commands.item(SymCommand::List, SymCommand::List, "");
    commands = commands.item(SymCommand::GetKeyProperties, SymCommand::GetKeyProperties, "");
    if capabilities.contains(&ObjectCapability::GenerateSymmetricKey) {
        commands = commands.item(SymCommand::Generate, SymCommand::Generate, "");
    }
    if capabilities.contains(&ObjectCapability::PutSymmetricKey) {
        commands = commands.item(SymCommand::Import, SymCommand::Import, "");
    }
    if capabilities.contains(&ObjectCapability::DeleteSymmetricKey) {
        commands = commands.item(SymCommand::Delete, SymCommand::Delete, "");
    }
    if capabilities.contains(&ObjectCapability::EncryptEcb) ||
        capabilities.contains(&ObjectCapability::EncryptCbc) {
    // if HashSet::from([
    //     ObjectCapability::EncryptEcb,
    //     ObjectCapability::EncryptCbc]).intersection(&capabilities).count() > 0 {
        commands = commands.item(SymCommand::Encrypt, SymCommand::Encrypt, "");
    }
    if capabilities.contains(&ObjectCapability::DecryptEcb) ||
        capabilities.contains(&ObjectCapability::DecryptCbc) {
    // if HashSet::from([
    //     ObjectCapability::DecryptEcb,
    //     ObjectCapability::DecryptCbc]).intersection(&capabilities).count() > 0 {
        commands = commands.item(SymCommand::Decrypt, SymCommand::Decrypt, "");
    }
    commands = commands.item(SymCommand::ReturnToMainMenu, SymCommand::ReturnToMainMenu, "");
    commands = commands.item(SymCommand::Exit, SymCommand::Exit, "");
    Ok(commands.interact()?)
}

fn get_all_sym_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let keys = session.list_objects_with_filter(
        0,
        ObjectType::SymmetricKey,
        "",
        ObjectAlgorithm::ANY,
        &Vec::new())?;
    Ok(keys)
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_sym_keys(session)?;
    list_objects(session, &keys)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_sym_keys(session)?)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key_algorithm = cliclack::select("Choose key algorithm:")
        .item(ObjectAlgorithm::Aes128, "AES128", "")
        .item(ObjectAlgorithm::Aes192, "AES192", "")
        .item(ObjectAlgorithm::Aes256, "AES256", "")
        .interact()?;

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::SymmetricKey, &AES_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = key_algorithm;

    cliclack::note("Generating AES key with:", get_new_key_note(&new_key))?;

    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating AES key...");
        let id = session
            .generate_aes_key(
                new_key.id, &new_key.label, &new_key.capabilities, &new_key.domains, key_algorithm)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated AES key with ID 0x{:04x} on the device", id))?;
    }
    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
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

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::SymmetricKey, &AES_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = key_algorithm;

    cliclack::note("Import AES key with:", get_new_key_note(&new_key))?;

    if cliclack::confirm("Import key?").interact()? {
        let id = session
            .import_aes_key(
                new_key.id, &new_key.label, &new_key.domains, &new_key.capabilities, key_algorithm, &key)?;
        cliclack::log::success(
            format!("Imported AES key with ID 0x{:04x} on the device", id))?;
    }
    Ok(())
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_sym_keys(session)?)
}

fn operate(session: &Session, authkey: &ObjectDescriptor, enc: bool) -> Result<(), MgmError> {

    let mut mode = cliclack::select("Select encryption mode");
    if (enc && authkey.capabilities.contains(&ObjectCapability::EncryptEcb)) ||
        (!enc && authkey.capabilities.contains(&ObjectCapability::DecryptEcb)) {
        mode = mode.item(AesMode::Ecb, "ECB", "");
    }
    if (enc && authkey.capabilities.contains(&ObjectCapability::EncryptCbc)) ||
        (!enc && authkey.capabilities.contains(&ObjectCapability::DecryptCbc)) {
        mode = mode.item(AesMode::Cbc, "CBC", "")
    }
    let mode = mode.interact()?;

    // let authkey_capabilities = get_permissible_capabilities(session, current_authkey)?;
    let key = match mode {
        AesMode::Ecb => get_op_key(
            session, authkey,
            [if enc {ObjectCapability::EncryptEcb} else {ObjectCapability::DecryptEcb}].to_vec().as_ref(),
            ObjectType::SymmetricKey,
            &[])?,
        AesMode::Cbc  => get_op_key(
            session, authkey,
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

fn get_new_key_note(key_desc: &ObjectDescriptor) -> String {
    key_desc.to_string()
            .replace("Sequence:  0\t", "")
            .replace("Origin: Generated\t", "")
            .replace("\t", "\n")
}