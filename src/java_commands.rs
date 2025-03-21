use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display};
use std::sync::LazyLock;
use openssl::{base64, pkey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use pem::Pem;
use yubihsmrs::error::Error;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectOrigin, ObjectType};
use yubihsmrs::Session;
use asym_commands::{gen_asym_key, get_attestation_cert, import_asym_key};

use error::MgmError;
use MAIN_STRING;
use util::{BasicDescriptor, convert_handlers, get_file_path, get_new_object_basics, get_op_key, list_objects,
           print_object_properties, read_file_bytes, read_pem_file, select_multiple_objects, write_bytes_to_file};

use crate::util::{delete_objects};

static JAVA_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > SunPKCS11 keys", MAIN_STRING));

const RSA_KEY_ALGORITHM: [ObjectAlgorithm; 3] = [
    ObjectAlgorithm::Rsa2048,
    ObjectAlgorithm::Rsa3072,
    ObjectAlgorithm::Rsa4096];

const EC_KEY_ALGORITHM: [ObjectAlgorithm; 8] = [
    ObjectAlgorithm::EcP224,
    ObjectAlgorithm::EcP256,
    ObjectAlgorithm::EcP384,
    ObjectAlgorithm::EcP521,
    ObjectAlgorithm::EcK256,
    ObjectAlgorithm::EcBp256,
    ObjectAlgorithm::EcBp384,
    ObjectAlgorithm::EcBp512];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum JavaCommand {
    #[default]
    List,
    Generate,
    Import,
    Delete,
    ReturnToMainMenu,
    Exit,
}

impl Display for JavaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JavaCommand::List => write!(f, "List"),
            JavaCommand::Generate => write!(f, "Generate"),
            JavaCommand::Import => write!(f, "Import"),
            JavaCommand::Delete => write!(f, "Delete"),
            JavaCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            JavaCommand::Exit => write!(f, "Exit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AsymKeyTypes {
    #[default]
    Rsa,
    Ec,
    Ed,
}

pub fn exec_java_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        println!("\n{}", JAVA_STRING.to_string());

        cliclack::note("",
            "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate \
        are store in the device with the same ObjectID".to_string())?;


        let cmd = get_command(authkey)?;
        let res = match cmd {
            JavaCommand::List => {
                println!("\n{} > {}\n", JAVA_STRING.to_string(), JavaCommand::List);
                list(session)
            },
            JavaCommand::Generate => {
                println!("\n{} > {}\n", JAVA_STRING.to_string(), JavaCommand::Generate);
                generate(session, authkey)
            },
            JavaCommand::Import => {
                println!("\n{} > {}\n", JAVA_STRING.to_string(), JavaCommand::Import);
                import(session, authkey)
            },
            JavaCommand::Delete => {
                println!("\n{} > {}\n", JAVA_STRING.to_string(), JavaCommand::Delete);
                delete(session)
            },
            JavaCommand::ReturnToMainMenu => return Ok(()),
            JavaCommand::Exit => std::process::exit(0),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}


fn get_command(authkey: &ObjectDescriptor) -> Result<JavaCommand, MgmError> {
    let auth_capabilities = &authkey.capabilities;

    let mut commands = cliclack::select("");
    commands = commands.item(JavaCommand::List, JavaCommand::List, "");

    if auth_capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) &&
        auth_capabilities.contains(&ObjectCapability::PutOpaque) &&
        auth_capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(JavaCommand::Generate, JavaCommand::Generate, "");
    }

    if auth_capabilities.contains(&ObjectCapability::PutAsymmetricKey) &&
        auth_capabilities.contains(&ObjectCapability::PutOpaque) &&
        auth_capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(JavaCommand::Import, JavaCommand::Import, "");
    }

    if auth_capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) &&
        auth_capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands = commands.item(JavaCommand::Delete, JavaCommand::Delete, "");
    }
    commands = commands.item(JavaCommand::ReturnToMainMenu, JavaCommand::ReturnToMainMenu, "");
    commands = commands.item(JavaCommand::Exit, JavaCommand::Exit, "");
    Ok(commands.interact()?)
}


fn get_all_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.list_objects_with_filter(
        0,
        ObjectType::Opaque,
        "",
        ObjectAlgorithm::OpaqueX509Certificate,
        &Vec::new())?;
    keys.retain(|k| session.get_object_info(k.object_id, ObjectType::AsymmetricKey).is_ok());
    keys.iter_mut().for_each(|x| x.object_type = ObjectType::AsymmetricKey);
    Ok(keys)
    // convert_handlers(session, &keys)
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_keys(session)?;
    // cliclack::log::remark(format!("Found {} objects", keys.len()))?;
    // for k in keys {
    //     println!("  {}", BasicDescriptor::from(k));
    // }
    // Ok(())
    list_objects(session, &keys)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_keys(session)?;
    if keys.is_empty() {
        cliclack::log::info("No java keys available for removal")?;
        return Ok(());
    }

    let selected_keys = select_multiple_objects(
        "Select keys to delete", convert_handlers(session, &keys)?, false)?;

    // let mut selected_keys = cliclack::multiselect(
    //     "Select JAVA keys to delete. Press the space button to select and unselect item. Press 'Enter' when done.");
    // selected_keys = selected_keys.required(false);
    // for key in all_java_keys {
    //     selected_keys = selected_keys.item(key.clone(), BasicDescriptor::from(key), "");
    // }
    // let selected_keys = selected_keys.interact()?;
    if !selected_keys.is_empty() && cliclack::confirm(
        "All selected key(s) will be deleted and cannot be recovered. Delete anyway?").interact()? {
        for key in selected_keys {
            if let Err(err) = delete_java_key(session, key.id) {
                cliclack::log::error(format!("Failed to delete object with ID 0x{:04x}. {}", key.id, err))?;
                continue;
            };
        }
    }
    Ok(())
}

fn delete_java_key(session: &Session, id: u16) -> Result<(), MgmError>{
    session.delete_object(id, ObjectType::AsymmetricKey)?;
    cliclack::log::info(
        format!("Deleted asymmetric key with ID 0x{:04x} from the device", id))?;
    match session.delete_object(id, ObjectType::Opaque) {
        Ok(()) => cliclack::log::info(format!("Deleted X509Certificate with ID 0x{:04x} from the device", id))?,
        _ => {}
    };
    // if cert_id != 0 {
    //     session.delete_object(cert_id, ObjectType::Opaque)?;
    //     cliclack::log::info(
    //         format!("Deleted X509Certificate with ID 0x{:04x} from the device", cert_id))?;
    // }
    Ok(())
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key = gen_asym_key(session, authkey)?;
    cliclack::log::step(
        format!("Stored asymmetric key with ID 0x{:04x} on the device", key.id))?;

    let selfsigned_cert = match get_attestation_cert(session, authkey, key.id, key.id) {
        Ok(c) => c,
        Err(err) => {
            cliclack::log::error(
                format!("Failed to generate selfsigned certificate. Deleting 0x{:04x} key", key.id))?;
            delete_java_key(session, key.id)?;
            return Err(err)
        }
    };
    match session.import_opaque(
        key.id,
            &key.label,
            &key.domains,
            &[ObjectCapability::ExportableUnderWrap],
            ObjectAlgorithm::OpaqueX509Certificate,
            &selfsigned_cert) {
        Ok(cert) => cert,
        Err(err) => {
            cliclack::log::error(
                format!("Failed to import selfsigned certificate. Deleting 0x{:04x} key", key.id))?;
            delete_java_key(session, key.id)?;
            return Err(MgmError::LibYubiHsm(err))
        }
    };

    cliclack::log::step(
        format!("Stored selfsigned certificate with ID 0x{:04x} on the device", key.id))?;

    cliclack::log::success(
        format!("Stored JAVA key with ID 0x{:04x} on the device", key.id))?;

    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor ) -> Result<(), MgmError> {
    let key = import_asym_key(
        session, authkey, get_file_path("Enter absolute path to PEM file containing private key:")?)?;

    let pem = read_pem_file(
        get_file_path("Enter absolute path to PEM file containing X509Certificate:")?)?;
    let cert_bytes = pem.contents();

    match openssl::x509::X509::from_der(cert_bytes) {
        Ok(cert) => {
            match session
                .import_cert(key.id, &key.label, &key.domains, &[ObjectCapability::ExportableUnderWrap], &cert.to_pem()?) {
                Ok(_) => cliclack::log::success(format!("Imported X509Certificate with ID 0x{:04x} on the device", key.id))?,
                Err(err) => {
                    cliclack::log::error(
                        format!("Failed to import X509Certificate from file. Deleting 0x{:04x} key", key.id))?;
                    session.delete_object(key.id, ObjectType::AsymmetricKey)?;
                    return Err(MgmError::LibYubiHsm(err))
                }
            };
        }
        Err(cert_err) => {
            cliclack::log::error(format!("No X509Certificate found. Deleting 0x{:04x} key", key.id))?;
            session.delete_object(key.id, ObjectType::AsymmetricKey)?;
            return Err(MgmError::OpenSSLError(cert_err));
        }
    }

    Ok(())
}
