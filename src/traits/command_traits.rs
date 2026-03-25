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

use strum::IntoEnumIterator;
use yubihsmrs::object::{ObjectCapability, ObjectDescriptor};
use crate::common::util::contains_all;

/// Trait implemented by per-module command enums.
/// Each variant knows its own label, description, and required capabilities.
pub trait Command: Copy + Eq + IntoEnumIterator {
    fn label(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn required_capabilities(&self) -> &'static [ObjectCapability];
    fn require_all_capabilities(&self) -> bool {
        false
    }

    fn is_authorized(&self, authkey: &ObjectDescriptor) -> bool {
        let caps = self.required_capabilities();
        if caps.is_empty() {
            return true;
        }
        if self.require_all_capabilities() {
            contains_all(&authkey.capabilities, caps)
        } else {
            caps.iter().any(|cap| authkey.capabilities.contains(cap))
        }
    }

    fn authorized_commands(authkey: &ObjectDescriptor) -> Vec<Self> {
        Self::iter()
            .filter(|cmd| cmd.is_authorized(authkey))
            .collect()
    }
}


#[cfg(test)]
mod tests {
    use yubihsmrs::object::ObjectType;
    use super::*;
    use strum_macros::EnumIter;
// ══════════════════════════════════════════════
//  MgmCommand::is_authkey_authorized
// ══════════════════════════════════════════════

    #[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
    enum TestCommand {
        List,
        Generate,
        Sign,
    }

    impl Command for TestCommand {
        fn label(&self) -> &'static str {
            unimplemented!()
        }

        fn description(&self) -> &'static str {
            unimplemented!()
        }

        fn required_capabilities(&self) -> &'static [ObjectCapability] {
            match self {
                Self::List => &[],
                Self::Generate => &[
                    ObjectCapability::GenerateAsymmetricKey,
                    ObjectCapability::SignPkcs,
                ],
                Self::Sign => &[
                    ObjectCapability::SignPkcs,
                    ObjectCapability::SignPss,
                    ObjectCapability::SignEcdsa,
                ],
            }
        }

        fn require_all_capabilities(&self) -> bool {
            match self {
                Self::List => false,
                Self::Generate => true,
                Self::Sign => false,
            }
        }
    }

    fn make_authkey_desc(caps: Vec<ObjectCapability>) -> ObjectDescriptor {
        let mut desc = ObjectDescriptor::new();
        desc.id = 1;
        desc.object_type = ObjectType::AuthenticationKey;
        desc.capabilities = caps;
        desc
    }

    #[test]
    fn test_authz_no_required_caps_always_true() {
        let authkey = make_authkey_desc(vec![]);
        assert!(TestCommand::List.is_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_all_has_all() {
        let authkey = make_authkey_desc(vec![
            ObjectCapability::GenerateAsymmetricKey,
            ObjectCapability::SignPkcs,
            ObjectCapability::ExportWrapped, // extra cap is fine
        ]);
        assert!(TestCommand::Generate.is_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_all_missing_one() {
        // Missing SignPkcs
        let authkey = make_authkey_desc(vec![ObjectCapability::GenerateAsymmetricKey]);
        assert!(!TestCommand::Generate.is_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_any_has_one() {
        // Only has SignPss — that's enough with require_all=false
        let authkey = make_authkey_desc(vec![ObjectCapability::SignPss]);
        assert!(TestCommand::Sign.is_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_any_has_none() {
        // Has completely unrelated capabilities
        let authkey = make_authkey_desc(vec![ObjectCapability::ExportWrapped]);
        assert!(!TestCommand::Sign.is_authorized(&authkey));
    }
}