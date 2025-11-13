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
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::types::{ImportObjectSpec, ObjectSpec};
use crate::backend::error::MgmError;

pub trait Obtainable {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError>;

    fn get_object_algorithms() -> Vec<MgmAlgorithm>;

    fn get_object_capabilities(object_algorithm: &ObjectAlgorithm) -> Vec<ObjectCapability>;
}

// /// Trait for fetching and formatting a single object.
// pub trait Describable {
//     fn get_properties(&self, session: &Session, id: u16, object_type: ObjectType) -> Result<ObjectDescriptor, MgmError>;
//
//     fn print(&self, desc: &ObjectDescriptor) -> String {
//         desc.to_string()
//     }
// }

/// Trait for generating a new object.
pub trait Generatable {
    fn generate(&self, session: &Session, spec: &ObjectSpec) -> Result<u16, MgmError>;
}

/// Trait for importing an existing object.
pub trait Importable {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError>;
}

/// Trait for deleting an existing object.
pub trait Deletable {
    fn delete(&self, session: &Session, object_id: u16, object_type: ObjectType) -> Result<(), MgmError>;

    fn delete_multiple(&self, session: &Session, objects: &Vec<ObjectDescriptor>) -> Vec<(ObjectDescriptor, MgmError)> {
        let mut failed:Vec<(ObjectDescriptor, MgmError)> = Vec::new();
        for object in objects {
            if let Err(e) = self.delete(session, object.id, object.object_type) {
                failed.push((object.clone(), e));
            }
        }
        failed
    }
}
