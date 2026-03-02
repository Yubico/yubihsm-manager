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

use super::utils::*;
use yubihsmrs::object::ObjectAlgorithm;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::device::DeviceOperations;

// ═══════════════════════════════════════════════
//  A1: get_device_info
// ═══════════════════════════════════════════════

#[test]
fn test_get_device_info() {
    let (hsm, _) = open_session();
    let info = hsm.get_device_info().expect("get_device_info failed");
    let info_str = format!("{}", info);
    assert!(!info_str.is_empty(), "Device info should not be empty");
}

// ═══════════════════════════════════════════════
//  A2: get_device_pubkey — 65 bytes, starts with 0x04
// ═══════════════════════════════════════════════

#[test]
fn test_get_device_pubkey() {
    let (hsm, _) = open_session();
    let pubkey = hsm.get_device_pubkey().expect("get_device_pubkey failed");
    assert_eq!(pubkey.len(), 65, "Should be 65 bytes (uncompressed EcP256)");
    assert!(AsymmetricOperations::get_pubkey_pem(ObjectAlgorithm::EcP256, &pubkey).is_ok());
}

// ═══════════════════════════════════════════════
//  A3: DeviceOperations::get_random
// ═══════════════════════════════════════════════

#[test]
fn test_get_random() {
    let (_hsm, session) = open_session();
    let random = DeviceOperations::get_random(&session, 32).expect("get_random failed");
    assert_eq!(random.len(), 32);

    let random2 = DeviceOperations::get_random(&session, 32).expect("get_random (2nd) failed");
    assert_ne!(random, random2, "Two calls should return different data");
}