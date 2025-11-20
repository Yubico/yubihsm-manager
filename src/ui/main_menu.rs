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
use crate::ui::{asym_menu, auth_menu, device_menu, java_menu, ksp_menu, sym_menu, wrap_menu};
use crate::ui::utils::{delete_objects, display_object_properties, display_menu_headers};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::types::{SelectionItem, MgmCommandType};
use crate::backend::main_ops::{MgmObjectType, FilterType, MainOps};

static MAIN_HEADER: &str = "YubiHSM Manager";

pub fn exec_main_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        display_menu_headers(&[MAIN_HEADER],
                             "Operations applicable for all objects on the YubiHSM")?;

        let cmd = YubihsmUi::select_command(&Cmdline, &MainOps::get_authorized_commands(authkey))?;

        if cmd.command != MgmCommandType::GotoDevice {
            display_menu_headers(&[crate::MAIN_HEADER, cmd.label], cmd.description)?;
        }

        let res = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => print_key_properties(session),
            MgmCommandType::Delete => delete(session, authkey),
            MgmCommandType::Generate => generate(session, authkey),
            MgmCommandType::Import => import(session, authkey),
            MgmCommandType::GotoKey => goto_key(session, authkey),
            MgmCommandType::GotoSpecialCase => goto_special_case(session, authkey),
            MgmCommandType::GotoDevice => device_menu::exec_main_command(session, authkey),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    let types = YubihsmUi::select_one_item(
        &Cmdline,
        &SelectionItem::get_items(&[
            FilterType::All,
            FilterType::Id(0),
            FilterType::Type(vec![]),
            FilterType::Label("".to_string())]),
            Some(&FilterType::All),
            None
    )?;

    let objects = match types {
        FilterType::All => MainOps::get_all_objects(session, FilterType::All)?,
        FilterType::Id(_) => {
            let id = YubihsmUi::get_object_id(&Cmdline)?;
            MainOps::get_all_objects(session, FilterType::Id(id))?
        },
        FilterType::Type(_) => {
            let types = YubihsmUi::select_multiple_items(
                &Cmdline,
                &SelectionItem::get_items(&MainOps::get_filtrable_types()),
                &[],
                false,
                Some("\nSelect object types:")
            )?;
            MainOps::get_all_objects(session, FilterType::Type(types))?
        },
        FilterType::Label(_) => {
            let label = YubihsmUi::get_object_label(&Cmdline, "")?;
            MainOps::get_all_objects(session, FilterType::Label(label))?
        },
    };
    YubihsmUi::display_objects_basic(&Cmdline, &objects)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&MainOps::get_all_objects(session, FilterType::All)?)
}

fn delete(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    delete_objects(session, &MainOps::get_objects_for_delete(session, authkey)?)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type: MgmObjectType = YubihsmUi::select_one_item(
        &Cmdline,
        &SelectionItem::get_items(&MainOps::get_generatable_types(authkey)),
        None,
        Some("\nSelect object type:")
    )?;
    match _type {
        MgmObjectType::Asymmetric => asym_menu::generate(session, authkey),
        MgmObjectType::Symmetric => sym_menu::generate(session, authkey),
        MgmObjectType::Wrap => wrap_menu::generate(session, authkey),
        MgmObjectType::Java => java_menu::generate(session, authkey),
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
        MgmObjectType::Asymmetric | MgmObjectType::Certificate => asym_menu::import(session, authkey),
        MgmObjectType::Symmetric => sym_menu::import(session, authkey),
        MgmObjectType::Wrap => wrap_menu::import(session, authkey),
        MgmObjectType::Java => java_menu::import(session, authkey),
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
        MgmObjectType::Asymmetric | MgmObjectType::Certificate => asym_menu::exec_asym_command(session, authkey),
        MgmObjectType::Symmetric => sym_menu::exec_sym_command(session, authkey),
        MgmObjectType::Wrap => wrap_menu::exec_wrap_command(session, authkey),
        MgmObjectType::Authentication => auth_menu::exec_auth_command(session, authkey),
        _ => Ok(())
    }
}

fn goto_special_case(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type: MgmObjectType = YubihsmUi::select_one_item(
        &Cmdline,
        &SelectionItem::get_items(&MainOps::get_special_case_types()),
        None,
        Some("\nSelect object type:")
    )?;
    match _type {
        MgmObjectType::Java => java_menu::exec_java_command(session, authkey),
        MgmObjectType::Ksp => ksp_menu::guided_ksp_setup(session, authkey),
        _ => Ok(())
    }
}
