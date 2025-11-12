use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::object_ops::Importable;
use crate::backend::types::{ImportObjectSpec, YhAlgorithm};
use crate::backend::common::get_descriptors_from_handlers;
use crate::backend::object_ops::{Deletable, Obtainable};
use crate::error::MgmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserType {
    #[default]
    AsymUser,
    AsymAdmin,
    Auditor,
    BackupAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationType {
    #[default]
    PasswordDerived,
    Ecp256,
}

pub struct AuthOps;

impl Obtainable for AuthOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let keys = session.list_objects_with_filter(
            0,
            ObjectType::AuthenticationKey,
            "",
            ObjectAlgorithm::ANY,
            &Vec::new())?;
        get_descriptors_from_handlers(session, &keys)
    }

    fn get_object_algorithms() -> Vec<YhAlgorithm> {
        Vec::new()
    }

    fn get_object_capabilities(_: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        unimplemented!()
    }
}

impl Deletable for AuthOps {
    fn delete(&self, session: &Session, object_id: u16, _: ObjectType) -> Result<(), MgmError> {
        session.delete_object(object_id, ObjectType::AuthenticationKey)?;
        Ok(())
    }
}

impl Importable for AuthOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        let id = match spec.object.algorithm {
            ObjectAlgorithm::Aes128YubicoAuthentication => {
                session.import_authentication_key(
                    spec.object.id,
                    &spec.object.label,
                    &spec.object.domains,
                    &spec.object.capabilities,
                    &spec.object.delegated_capabilities,
                    &spec.data[0])?
            },
            ObjectAlgorithm::Ecp256YubicoAuthentication => {
                session.import_authentication_publickey(
                    spec.object.id,
                    &spec.object.label,
                    &spec.object.domains,
                    &spec.object.capabilities,
                    &spec.object.delegated_capabilities,
                    &spec.data[0])?
            }
            _ => {
                return Err(MgmError::InvalidInput(
                    format!("Unsupported algorithm for authentication key: {}", spec.object.algorithm)
                ));
            }
        };
        Ok(id)
    }
}

impl AuthOps {
    pub const KEY_USER_CAPABILITIES: [ObjectCapability; 13] = [
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa,
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::SignAttestationCertificate,
        ObjectCapability::EncryptEcb,
        ObjectCapability::EncryptCbc,
        ObjectCapability::DecryptEcb,
        ObjectCapability::DecryptCbc,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const KEY_ADMIN_CAPABILITIES: [ObjectCapability; 9] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::PutAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey,
        ObjectCapability::PutOpaque,
        ObjectCapability::DeleteOpaque,
        ObjectCapability::GenerateSymmetricKey,
        ObjectCapability::PutSymmetricKey,
        ObjectCapability::DeleteSymmetricKey,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const AUDITOR_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::GetLogEntries,
        ObjectCapability::ExportableUnderWrap,
    ];
}