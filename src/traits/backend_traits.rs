/*
 * Copyright 2025 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::common::{get_delegated_capabilities, get_authorized_commands};
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::types::MgmCommand;
use crate::backend::error::MgmError;
use crate::backend::types::NewObjectSpec;

pub trait YubihsmOperations {

    fn get_commands(&self) -> Vec<MgmCommand>;
    fn get_authorized_commands(&self, authkey: &ObjectDescriptor) -> Vec<MgmCommand> {
        let commands = self.get_commands();
        get_authorized_commands(authkey, &commands)
    }

    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError>;
    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm>;

    fn get_object_capabilities(
        &self,
        object_type: Option<ObjectType>,
        object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError>;
    fn get_applicable_capabilities(
        &self,
        authkey: &ObjectDescriptor,
        object_type: Option<ObjectType>,
        object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        let auth_delegated = get_delegated_capabilities(authkey);
        let mut caps = self.get_object_capabilities(object_type, object_algorithm)?;
        caps.retain(|c| auth_delegated.contains(c));
        Ok(caps)
    }

    fn generate(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError>;
    fn import(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError>;
    fn delete(&self, session: &Session, object_id: u16, object_type: ObjectType) -> Result<(), MgmError> {
        Ok(session.delete_object(object_id, object_type)?)
    }
}
