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
use crate::backend::main_ops::MgmObjectType;
use crate::ui;
use crate::backend::object_ops::Deletable;
use crate::ui::cmd_utils::{print_failed_delete, select_delete_objects};
use crate::ui::cmd_utils::print_object_properties;
use crate::backend::main_ops::FilterType;
use crate::ui::cmd_utils::{get_id, get_label, list_objects};
use crate::backend::main_ops::MainOps;
use crate::backend::types::YhCommand;
use crate::ui::cmd_utils::{print_menu_headers, select_command};
use crate::backend::error::MgmError;

static MAIN_HEADER: &str = "YubiHSM Manager";

pub fn exec_main_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        print_menu_headers(&[MAIN_HEADER]);

        let cmd = select_command(&MainOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, cmd.label]);

        let res = match cmd.command {
            YhCommand::List => list(session),
            YhCommand::GetKeyProperties => print_key_properties(session),
            YhCommand::Delete => delete(session, authkey),
            YhCommand::Generate => generate(session, authkey),
            YhCommand::Import => import(session, authkey),
            YhCommand::GotoKey => goto_key(session, authkey),
            YhCommand::GotoSpecialCase => goto_special_case(session, authkey),
            YhCommand::GotoDevice => ui::device_menu::exec_main_command(session, authkey),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    let types = cliclack::select("")
        .item(FilterType::All, FilterType::All, "")
        .item(FilterType::Id(0), FilterType::Id(0), "")
        .item(FilterType::Type(vec![]), FilterType::Type(vec![]), "")
        .item(FilterType::Label("".to_string()), FilterType::Label("".to_string()), "")
        .interact()?;

    let objects = match types {
        FilterType::All => MainOps::get_all_objects(session, FilterType::All)?,
        FilterType::Id(_) => {
            let id = get_id()?;
            MainOps::get_all_objects(session, FilterType::Id(id))?
        },
        FilterType::Type(_) => {
            let types = select_object_type(&MainOps::get_filtrable_types(), true)?;
            MainOps::get_all_objects(session, FilterType::Type(types))?
        },
        FilterType::Label(_) => {
            let label = get_label()?;
            MainOps::get_all_objects(session, FilterType::Label(label))?
        },
    };
    list_objects(&objects)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(&MainOps::get_all_objects(session, FilterType::All)?)
}

fn delete(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let objects = select_delete_objects(&MainOps::get_objects_for_delete(session, authkey)?)?;
    let failed = Deletable::delete_multiple(&MainOps, session, &objects);
    print_failed_delete(&failed)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type = select_object_type(&MainOps::get_generatable_types(authkey), false)?[0].to_owned();
    match _type {
        MgmObjectType::Asymmetric => ui::asym_menu::generate(session, authkey),
        MgmObjectType::Symmetric => ui::sym_menu::generate(session, authkey),
        MgmObjectType::Wrap => ui::wrap_menu::generate(session, authkey),
        MgmObjectType::Java => ui::java_menu::generate(session, authkey),
        _ => Ok(())
    }
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type = select_object_type(&MainOps::get_importable_types(authkey), false)?[0].to_owned();
    match _type {
        MgmObjectType::Asymmetric | MgmObjectType::Certificate => ui::asym_menu::import(session, authkey),
        MgmObjectType::Symmetric => ui::sym_menu::import(session, authkey),
        MgmObjectType::Wrap => ui::wrap_menu::import(session, authkey),
        MgmObjectType::Java => ui::java_menu::import(session, authkey),
        _ => Ok(())
    }
}

fn goto_key(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type = select_object_type(&MainOps::get_key_operation_types(), false)?[0].to_owned();
    match _type {
        MgmObjectType::Asymmetric | MgmObjectType::Certificate => ui::asym_menu::exec_asym_command(session, authkey),
        MgmObjectType::Symmetric => ui::sym_menu::exec_sym_command(session, authkey),
        MgmObjectType::Wrap => ui::wrap_menu::exec_wrap_command(session, authkey),
        MgmObjectType::Authentication => ui::auth_menu::exec_auth_command(session, authkey),
        _ => Ok(())
    }
}

fn goto_special_case(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let _type = select_object_type(&MainOps::get_special_case_types(), false)?[0].to_owned();
    match _type {
        MgmObjectType::Java => ui::java_menu::exec_java_command(session, authkey),
        MgmObjectType::Ksp => ui::ksp_menu::guided_ksp_setup(session, authkey),
        _ => Ok(())
    }
}


fn select_object_type(types: &[MgmObjectType], multiple: bool) -> Result<Vec<MgmObjectType>, MgmError> {
    let _types = if multiple {
        let mut ts = cliclack::multiselect("\nSelect object types:").required(false);
        for t in types {
            ts = ts.item(t.clone(), t.to_string(), "");
        }
        ts.interact()?
    } else {
        let mut t = cliclack::select("\nSelect object type:");
        for _t in types {
            t = t.item(_t.clone(), _t.to_string(), "");
        }
        vec![t.interact()?]
    };
    Ok(_types)
}