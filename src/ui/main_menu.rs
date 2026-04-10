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

use yubihsmrs::object::ObjectDescriptor;
use yubihsmrs::Session;
use crate::traits::ui_traits::YubihsmUi;
use crate::traits::command_traits::Command;
use crate::ui::wrap_menu::WrapMenu;
use crate::ui::sym_menu::SymmetricMenu;
use crate::ui::ksp_menu::Ksp;
use crate::ui::java_menu::JavaMenu;
use crate::ui::device_menu::DeviceMenu;
use crate::ui::auth_menu::AuthenticationMenu;
use crate::ui::asym_menu::AsymmetricMenu;
use crate::ui::helper_operations::{list_objects, display_menu_headers};
use crate::common::error::MgmError;
use crate::common::types::SelectionItem;
use crate::hsm_operations::main_ops::{MainCommand, SpecialOpCommand, FilterType, MainOperations};
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

            let cmd = self.ui.select_command(&MainCommand::authorized_commands(authkey))?;

            if cmd != MainCommand::GotoDevice {
                display_menu_headers(&self.ui, &[crate::MAIN_HEADER, cmd.label()], cmd.description())?;
            }

            let res = match cmd {
                MainCommand::List => list_objects(&self.ui, &MainOperations, session),
                MainCommand::Search => self.search(session),
                MainCommand::GotoAsym => AsymmetricMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MainCommand::GotoSym => SymmetricMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MainCommand::GotoWrap => WrapMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MainCommand::GotoAuth => AuthenticationMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MainCommand::GotoSpecialOps => self.goto_special_ops(session, recorder, authkey),
                MainCommand::GotoDevice => DeviceMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
                MainCommand::Exit => std::process::exit(0),
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
                    Some("\nSelect types:")
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

    fn goto_special_ops(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        match self.ui.select_command(&SpecialOpCommand::authorized_commands(authkey))? {
            SpecialOpCommand::SunPkcs11 => JavaMenu::new(self.ui.clone()).exec_command(session, recorder, authkey),
            SpecialOpCommand::Ksp => Ksp::new(self.ui.clone()).guided_setup(session, authkey),
        }
    }
}