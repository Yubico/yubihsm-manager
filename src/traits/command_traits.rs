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