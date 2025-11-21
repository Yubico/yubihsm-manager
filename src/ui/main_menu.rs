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
use crate::ui::utils::{list_objects, delete_objects, display_menu_headers, generate_object};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::traits::backend_traits::YubihsmOperations;
use crate::backend::error::MgmError;
use crate::backend::sym::SymOps;
use crate::backend::wrap::WrapOps;
use crate::backend::types::{SelectionItem, MgmCommandType};
use crate::backend::main_ops::{MgmObjectType, FilterType, MainOps};
use crate::backend::asym::AsymOps;

static MAIN_HEADER: &str = "YubiHSM Manager";

pub struct MainMenu;

impl MainMenu {
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&[MAIN_HEADER],
                                 "Operations applicable for all objects on the YubiHSM")?;

            let cmd = YubihsmUi::select_command(&Cmdline, &MainOps.get_authorized_commands(authkey))?;

            if cmd.command != MgmCommandType::GotoDevice {
                display_menu_headers(&[crate::MAIN_HEADER, cmd.label], cmd.description)?;
            }

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&MainOps, session),
                MgmCommandType::Search => Self::search(session),
                MgmCommandType::Delete => delete_objects(&MainOps, session, &MainOps::get_objects_for_delete(session, authkey)?),
                MgmCommandType::Generate => Self::generate(session, authkey),
                MgmCommandType::Import => Self::import(session, authkey),
                MgmCommandType::GotoKey => Self::goto_key(session, authkey),
                MgmCommandType::GotoDevice => DeviceMenu.exec_command(session, authkey),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
            }
        }
    }

    fn search(session: &Session) -> Result<(), MgmError> {
        let types = YubihsmUi::select_one_item(
            &Cmdline,
            &SelectionItem::get_items(&[
                FilterType::Id(0),
                FilterType::Type(vec![]),
                FilterType::Label("".to_string())]),
            None,
            None
        )?;

        let objects = match types {
            FilterType::Id(_) => {
                let id = YubihsmUi::get_object_id(&Cmdline)?;
                MainOps::get_filtered_objects(session, FilterType::Id(id))?
            },
            FilterType::Type(_) => {
                let types = YubihsmUi::select_multiple_items(
                    &Cmdline,
                    &SelectionItem::get_items(&MainOps::get_search_by_types()),
                    &[],
                    false,
                    Some("\nSelect object types:")
                )?;
                MainOps::get_filtered_objects(session, FilterType::Type(types))?
            },
            FilterType::Label(_) => {
                let label = YubihsmUi::get_object_label(&Cmdline, "")?;
                MainOps::get_filtered_objects(session, FilterType::Label(label))?
            },
        };
        YubihsmUi::display_objects_full(&Cmdline, &objects)
    }

    fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let _type: MgmObjectType = YubihsmUi::select_one_item(
            &Cmdline,
            &SelectionItem::get_items(&MainOps::get_generatable_types(authkey)),
            None,
            Some("\nSelect object type:")
        )?;
        match _type {
            MgmObjectType::Asymmetric => generate_object(&AsymOps, session, authkey, ObjectType::AsymmetricKey),
            MgmObjectType::Symmetric => generate_object(&SymOps, session, authkey, ObjectType::SymmetricKey),
            MgmObjectType::Wrap => generate_object(&WrapOps, session, authkey, ObjectType::WrapKey),
            _ => Ok(())
        }
    }

    fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let _type: MgmObjectType = YubihsmUi::select_one_item(
            &Cmdline,
            &SelectionItem::get_items(&MainOps::get_importable_types(authkey)),
            None,
            Some("\nSelect object type:")
        )?;
        match _type {
            MgmObjectType::Asymmetric | MgmObjectType::Certificate => AsymmetricMenu::import(session, authkey),
            MgmObjectType::Symmetric => SymmetricMenu.import(session, authkey),
            MgmObjectType::Wrap => WrapMenu.import(session, authkey),
            _ => Ok(())
        }
    }

    fn goto_key(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let _type: MgmObjectType = YubihsmUi::select_one_item(
            &Cmdline,
            &SelectionItem::get_items(&MainOps::get_key_operation_types()),
            None,
            Some("\nSelect object type:")
        )?;
        match _type {
            MgmObjectType::Asymmetric | MgmObjectType::Certificate => AsymmetricMenu.exec_command(session, authkey),
            MgmObjectType::Symmetric => SymmetricMenu.exec_command(session, authkey),
            MgmObjectType::Wrap => WrapMenu.exec_command(session, authkey),
            MgmObjectType::Authentication => AuthenticationMenu.exec_command(session, authkey),
            MgmObjectType::Java => JavaMenu.exec_command(session, authkey),
            MgmObjectType::Ksp => Ksp.guided_setup(session, authkey),
        }
    }
}