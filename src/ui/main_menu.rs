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

use yubihsmrs::object::{ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::wrap_menu::WrapMenu;
use crate::ui::sym_menu::SymmetricMenu;
use crate::ui::ksp_menu::Ksp;
use crate::ui::java_menu::JavaMenu;
use crate::ui::device_menu::DeviceMenu;
use crate::ui::auth_menu::AuthenticationMenu;
use crate::ui::asym_menu::AsymmetricMenu;
use crate::ui::helper_operations::{list_objects, delete_objects, display_menu_headers, generate_object};
use crate::traits::operation_traits::YubihsmOperations;
use crate::common::error::MgmError;
use crate::common::types::{SelectionItem, MgmCommandType};
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::wrap::WrapOperations;
use crate::hsm_operations::main_ops::{FilterType, MainOperations};
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::script::script_recorder::SessionRecorder;

static MAIN_HEADER: &str = "YubiHSM Manager";

pub struct MainMenu<T: YubihsmUi + Clone> {
    ui: T,
}

impl<T: YubihsmUi + Clone> MainMenu<T> {

    pub fn new(interface: T) -> Self {
        MainMenu { ui: interface }
    }

    pub fn exec_command(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[MAIN_HEADER],
                                 "Operations applicable for all objects on the YubiHSM")?;

            let cmd = self.ui.select_command(&MainOperations.get_authorized_commands(authkey))?;

            if cmd.command != MgmCommandType::GotoDevice {
                display_menu_headers(&self.ui, &[crate::MAIN_HEADER, cmd.label], cmd.description)?;
            }

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &MainOperations, session),
                MgmCommandType::Search => self.search(session),
                MgmCommandType::Delete => delete_objects(&self.ui, recorder, &MainOperations, session, &MainOperations::get_objects_for_delete(session, authkey)?),
                MgmCommandType::Generate => self.generate(session, recorder, authkey),
                MgmCommandType::Import => self.import(session, recorder, authkey),
                MgmCommandType::GotoKey => self.goto_key(session, recorder, authkey),
                MgmCommandType::GotoDevice => DeviceMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                self.ui.display_error_message(e.to_string().as_str())
            }
        }
    }

    fn search(&self, session: &Session) -> Result<(), MgmError> {
        let types = self.ui.select_one_item(
            &SelectionItem::get_items(&[
                FilterType::Id(0),
                FilterType::Type(vec![]),
                FilterType::Label("".to_string())]),
            None,
            None
        )?;

        let objects = match types {
            FilterType::Id(_) => {
                let id = self.ui.get_object_id()?;
                MainOperations::get_filtered_objects(session, FilterType::Id(id))?
            },
            FilterType::Type(_) => {
                let types = self.ui.select_multiple_items(
                    &MainOperations::get_searchable_types(),
                    &[],
                    false,
                    Some("\nSelect object types:")
                )?;
                MainOperations::get_filtered_objects(session, FilterType::Type(types))?
            },
            FilterType::Label(_) => {
                let label = self.ui.get_object_label("")?;
                MainOperations::get_filtered_objects(session, FilterType::Label(label))?
            },
        };
        self.ui.display_objects_properties(&objects);
        Ok(())
    }

    fn generate(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let _type: ObjectType = self.ui.select_one_item(
            &MainOperations::get_generatable_types(authkey),
            None,
            Some("\nSelect type of object to generate:")
        )?;
        match _type {
            ObjectType::AsymmetricKey => generate_object(&self.ui, recorder, &AsymmetricOperations, session, authkey, ObjectType::AsymmetricKey),
            ObjectType::SymmetricKey => generate_object(&self.ui, recorder, &SymmetricOperations, session, authkey, ObjectType::SymmetricKey),
            ObjectType::WrapKey => generate_object(&self.ui, recorder, &WrapOperations, session, authkey, ObjectType::WrapKey),
            _ => Err(MgmError::Error("Object type out of scope".to_string()))
        }
    }

    fn import(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let _type: ObjectType = self.ui.select_one_item(
            &MainOperations::get_importable_types(authkey),
            None,
            Some("\nSelect type or object to import:")
        )?;
        match _type {
            ObjectType::AsymmetricKey => AsymmetricMenu::new(self.ui.clone()).import(session, recorder, authkey),
            ObjectType::SymmetricKey => SymmetricMenu::new(self.ui.clone()).import(session, recorder, authkey),
            ObjectType::WrapKey => WrapMenu::new(self.ui.clone()).import(session, recorder, authkey),
            ObjectType::AuthenticationKey => AuthenticationMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            _ => Err(MgmError::Error("Object type out of scope".to_string()))
        }
    }

    fn goto_key(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let cmd: MgmCommandType = self.ui.select_one_item(
            &MainOperations::get_key_operation_types(),
            None,
            Some("\nSelect key operations:")
        )?;
        match cmd {
            MgmCommandType::GotoAsym => AsymmetricMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            MgmCommandType::GotoSym => SymmetricMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            MgmCommandType::GotoWrap => WrapMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            MgmCommandType::GotoAuth => AuthenticationMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            MgmCommandType::GotoJava => JavaMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            MgmCommandType::GotoKsp => Ksp::new(self.ui.clone()).guided_setup(session, authkey),
            _ => Err(MgmError::Error("Operation type out of scope".to_string()))
        }
    }
}