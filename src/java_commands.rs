use std::fmt;
use std::fmt::{Display};
use std::sync::LazyLock;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use asym_commands::{gen_asym_key, get_attestation_cert, import_asym_key};

use error::MgmError;
use MAIN_STRING;
use util::{contains_all, convert_handlers, get_file_path, list_objects, read_pem_file, select_multiple_objects};

static JAVA_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > SunPKCS11 keys", MAIN_STRING));

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

pub fn exec_java_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        println!("\n{}", *JAVA_STRING);

        cliclack::note("",
            "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate \
        are store in the device with the same ObjectID".to_string())?;


        let cmd = get_command(authkey)?;
        let res = match cmd {
            JavaCommand::List => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::List);
                list(session)
            },
            JavaCommand::Generate => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Generate);
                generate(session, authkey)
            },
            JavaCommand::Import => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Import);
                import(session, authkey)
            },
            JavaCommand::Delete => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Delete);
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

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::GenerateAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate]) {
        commands = commands.item(JavaCommand::Generate, JavaCommand::Generate, "");
    }

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate]) {
        commands = commands.item(JavaCommand::Import, JavaCommand::Import, "");
    }

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::DeleteAsymmetricKey, ObjectCapability::DeleteOpaque]) {
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
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_keys(session)?;
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
    if let Ok(()) = session.delete_object(id, ObjectType::Opaque) {
        cliclack::log::info(format!("Deleted X509Certificate with ID 0x{:04x} from the device", id))?
    };
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
