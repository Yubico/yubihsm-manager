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

use yubihsmrs::{YubiHsm, Session};

// ─── Defaults ────────────────────────────────────────────────────────────────
pub const DEFAULT_CONNECTOR: &str = "http://127.0.0.1:12345";
pub const DEFAULT_AUTHKEY_ID: u16 = 1;
pub const DEFAULT_PASSWORD: &str = "password";

// ─── Session setup ───────────────────────────────────────────────────────────

/// Returns (`YubiHsm`, `Session`) using defaults or env-var overrides.
///
/// Connector URL: `YUBIHSM_CONNECTOR`  (default: `http://127.0.0.1:12345`)
/// Auth key ID:   `YUBIHSM_AUTHKEY`    (default: `1`)
/// Password:      `YUBIHSM_PASSWORD`   (default: `password`)
pub fn open_session() -> (YubiHsm, Session) {
    let connector = std::env::var("YUBIHSM_CONNECTOR")
        .unwrap_or_else(|_| DEFAULT_CONNECTOR.to_string());
    let authkey: u16 = std::env::var("YUBIHSM_AUTHKEY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_AUTHKEY_ID);
    let password = std::env::var("YUBIHSM_PASSWORD")
        .unwrap_or_else(|_| DEFAULT_PASSWORD.to_string());

    yubihsmrs::init().expect("Failed to initialize libyubihsm");
    let h = YubiHsm::new(&connector)
        .expect("Failed to create YubiHsm handle — is yubihsm-connector running?");
    let session = h.establish_session(authkey, &password, true)
                   .expect("Failed to open session — check authkey/password");
    (h, session)
}