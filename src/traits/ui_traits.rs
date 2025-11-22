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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain};
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::{MgmCommand, SelectionItem, NewObjectSpec};
use crate::hsm_operations::algorithms::MgmAlgorithm;

pub trait YubihsmUi {

    fn get_new_object_id(&self, default: u16) -> Result<u16, MgmError>;
    fn get_object_id(&self) -> Result<u16, MgmError>;

    fn get_password(&self, prompt: &str, confirm: bool) -> Result<String, MgmError>;

    fn get_object_label(&self, default: &str) -> Result<String, MgmError>;

    fn select_object_domains(&self, available_domains: &[ObjectDomain]) -> Result<Vec<ObjectDomain>, MgmError>;
    fn select_object_capabilities(&self,
                                  available_capabilities: &[ObjectCapability],
                                  preselected_capabilities: &[ObjectCapability],
                                  prompt: Option<&str>) -> Result<Vec<ObjectCapability>, MgmError>;

    fn select_command(&self, available_commands: &[MgmCommand]) -> Result<MgmCommand, MgmError>;
    fn select_algorithm(&self,
                        available_algorithms: &[MgmAlgorithm],
                        default_algorithm: Option<ObjectAlgorithm>,
                        prompt: Option<&str>) -> Result<ObjectAlgorithm, MgmError>;
    fn select_one_object(&self,
                         available_objects: &[ObjectDescriptor],
                         prompt: Option<&str>) -> Result<ObjectDescriptor, MgmError>;
    fn select_multiple_objects(&self,
                                available_objects: &[ObjectDescriptor],
                                preselect_all: bool,
                                prompt: Option<&str>) -> Result<Vec<ObjectDescriptor>, MgmError>;
    fn select_one_item<T: Clone+Eq>(&self,
                       items: &[SelectionItem<T>],
                       default_item: Option<&T>,
                       prompt: Option<&str>) -> Result<T, MgmError>;
    fn select_multiple_items<T: Clone+Eq>(&self,
                                    available_items: &[SelectionItem<T>],
                                    preselected_items: &[T],
                                    required: bool,
                                    prompt: Option<&str>) -> Result<Vec<T>, MgmError>;


    fn get_string_input(&self, prompt: &str, required: bool) -> Result<String, MgmError>;
    fn get_integer_input(&self, prompt: &str, required: bool, default: Option<usize>, placeholder: Option<&str>, min: usize, max: usize) -> Result<usize, MgmError>;
    fn get_path_input(&self, prompt: &str, required: bool, default: Option<&str>, placeholder: Option<&str>) -> Result<String, MgmError>;

    fn get_pem_filepath(&self, prompt: &str, required: bool, place_holder: Option<&str>) -> Result<String, MgmError>;
    fn get_certificate_filepath(&self, prompt: &str, required: bool, place_holder: Option<&str>) -> Result<String, MgmError>;
    fn get_public_eckey_filepath(&self, prompt: &str) -> Result<String, MgmError>;
    fn get_public_ecp256_filepath(&self, prompt: &str) -> Result<String, MgmError>;
    fn get_private_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError>;
    fn get_public_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError>;
    fn get_aes_key_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError>;
    fn get_aes_iv_hex(&self, prompt: &str, required: bool, default: Option<&str>) -> Result<Vec<u8>, MgmError>;
    fn get_aes_operation_input_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError>;

    fn get_split_aes_n_shares(&self, prompt: &str) -> Result<u8, MgmError>;
    fn get_split_aes_m_threshold(&self, prompt: &str, n_shares: u8) -> Result<u8, MgmError>;
    fn get_split_aes_share(&self, prompt: &str, share_length: Option<u8>) -> Result<String, MgmError>;


    fn display_objects_basic(&self, objects: &[ObjectDescriptor]) -> Result<(), MgmError>;
    fn display_objects_full(&self, objects: &[ObjectDescriptor]) -> Result<(), MgmError>;
    fn display_objects_spec(&self, objects: &[NewObjectSpec]) -> Result<(), MgmError>;

    fn display_success_message(&self, message: &str) -> Result<(), MgmError>;
    fn display_info_message(&self, message: &str) -> Result<(), MgmError>;
    fn display_note(&self, header: &str, note: &str) -> Result<(), MgmError>;
    fn display_warning(&self, message: &str) -> Result<(), MgmError>;
    fn display_error_message(&self, message: &str) -> Result<(), MgmError>;
    fn get_confirmation(&self, prompt: &str) -> Result<bool, MgmError>;
    fn get_warning_confirmation(&self, warning_message: &str) -> Result<bool, MgmError>;
    fn get_note_confirmation(&self, prompt: &str,  message: &str) -> Result<bool, MgmError>;

    fn clear_screen(&self) -> Result<(), MgmError>;
    fn start_spinner(&self, message: Option<&str>) -> Box<dyn SpinnerHandler>;
    fn stop_spinner(&self, spinner_handler: Box<dyn SpinnerHandler>, message: Option<&str>);
    // fn start_progress(&self, message: Option<&str>) -> Box<dyn ProgressBarHandler>;
    // fn stop_progress(&self, progress_handler: Box<dyn ProgressBarHandler>, message: Option<&str>);
}

pub trait SpinnerHandler {
    fn start(&mut self, message: Option<&str>);
    fn stop(&mut self, success_message: Option<&str>);
}

pub trait ProgressBarHandler {
    fn start(&mut self, message: Option<&str>);
    fn stop(&mut self, success_message: Option<&str>);
}