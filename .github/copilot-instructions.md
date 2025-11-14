---
name: voxide-agent
description: Voxide development guide (SQLite + sqlx, Argon2id, XChaCha20-Poly1305)
tools: ["read", "search", "edit"]
---

# Voxide Agent Brief

name: voxide-copilot-agent
description: >
Agent brief for assisting development of Voxide — a SQLite-backed, AEAD-encrypted password
manager CLI written in Rust using sqlx and Tokio. The agent should prioritize security,
correctness, and small iterative steps with tests.

objectives:
- Build a usable CLI password manager (voxide) with secure design.
- Use Argon2id KDF + XChaCha20-Poly1305 AEAD; never store the master password or key.
- Store metadata and entries in SQLite via sqlx; enforce schema and safe migrations.
- Provide clear, ergonomic CLI UX with strong defaults and helpful --help text.
- Maintain a crisp separation of concerns: crypto, models/db, vault service, CLI.

non_goals:
- Browser extensions, auto-fill, or network features.
- Multi-user sharing or remote sync.
- Persisting any plaintext secrets to disk or logs.
- Implementing OS-specific keychain integration in the MVP.

constraints:
- Rust stable; forbid unsafe by default.
- No plaintext secrets in logs, errors, or panics.
- Secrets must be wrapped in secrecy::Secret* or zeroize::Zeroizing.
- Each encryption operation must use a unique 24-byte nonce (XChaCha20).
- Associated Data (AD) must bind (service, username) to each entry.
- All crypto implemented using well-vetted crates; no custom crypto.
- Provide deterministic builds and pass CI: format, clippy (deny warnings), tests.

security_principles:
- KDF: Argon2id with configurable m_cost_kib, t_cost, p_cost; store salt+params only.
- AEAD: XChaCha20-Poly1305; store ciphertext+nonce; use AD=(service,username).
- Verifier: store (nonce, ciphertext) of a known constant "voxide-ok" to validate unlocks.
- Zeroization: master password, derived key, and plaintext buffers are wiped on drop.
- Atomicity: use temp file + rename for master-password rotation and bulk operations.
- Error messages do not leak existence or correctness of entries; generic "unlock failed".
- Backoff after failed unlock attempts to slow brute force (MVP-level sleep).

tech_stack:
rust: "stable"
runtime: tokio (rt-multi-thread, macros)
database: sqlite (sqlx 0.7, runtime-tokio-rustls, macros, time)
crypto:
kdf: argon2 0.5 (Argon2id, v0x13)
aead: chacha20poly1305 0.10 (XChaCha20-Poly1305)
secrecy: secrecy 0.8, zeroize 1.8
cli: clap 4.5 (derive)
serialization: serde 1.0 + serde_json
time: time 0.3 (Rfc3339)
ux: rpassword 7.3 (no-echo input)

repository_layout:
- src/main.rs            # CLI + command router
- src/db.rs              # connection pool, ensure_schema, helpers
- src/crypto.rs          # KDF derive_key, AEAD seal/open, nonce helpers
- src/models.rs          # Meta, Entry entities (+ FromRow + helpers)
- src/vault.rs           # (optional) thin service layer orchestration
- Cargo.toml
- README.md
- LICENSE
- .github/workflows/ci.yml

cli_commands:
- name: init
  desc: Initialize vault; create schema; store salt, kdf params, and verifier ciphertext.
- name: add
  args: [service, username]
  desc: Prompt secret; encrypt payload; insert entry.
- name: get
  args: [service, username]
  desc: Unlock vault; decrypt payload; print secret (later: clipboard).
- name: list
  desc: List (service, username, created_at) tuples.
- name: delete
  args: [service, username]
  desc: Remove entry after confirmation.
- name: change-master
  desc: Rotate master password; new salt/params; re-wrap all entries atomically.
- name: export
  args: [path]
  desc: Encrypted JSON bundle export for backup.
- name: import
  args: [path]
  desc: Import encrypted bundle into a new/empty vault.

entities:
Meta:
fields:
- version: i64
- kdf_salt: Vec<u8>
- kdf_params: String  # JSON of KdfParams
- created_at: String  # RFC3339 UTC
- verifier_nonce: Vec<u8>
- verifier_ct: Vec<u8>
helpers:
- get(): SELECT single meta row
- insert(): INSERT with params
- kdf_params_parse(): parse JSON -> KdfParams
Entry:
fields:
- id: i64
- service: String
- username: String
- nonce: Vec<u8>       # 24 bytes
- ciphertext: Vec<u8>  # AEAD(ct + tag)
- created_at: String
- updated_at: String
helpers:
- by_pair(service, username)
- insert(NewEntry)
- delete(service, username)
- list_pairs()

kdf_params_format:
algorithm: "argon2id"
version: "0x13"
m_cost_kib: 65536
t_cost: 3
p_cost: 1
key_len: 32

aead_policy:
algorithm: "XChaCha20-Poly1305"
nonce_bytes: 24
ad_encoding: >
Big-endian length-prefixed: [u32_be|service][bytes][u32_be|username][bytes]
encrypt:
input: zeroized JSON payload {password, notes?}
output: ciphertext (includes tag), stored with nonce
decrypt:
verify_tag: true
on_failure: "Unlock failed" or "Decryption failed" (no detail leak)

roadmap:
mvp:
- project_setup: cargo init, deps, fmt/clippy config
- schema_init: ensure_schema(meta+entries+unique index)
- init_cmd: prompt pw; derive key; store salt+params; create verifier
- add_cmd: unlock; zeroized plaintext; nonce; aead.seal; insert
- get_cmd: unlock; fetch row; aead.open; print secret
- list_cmd: show service/username/created_at
- delete_cmd: remove entry
- tests_unit: kdf determinism, aead roundtrip, tamper failure
- tests_integration: init→add→get→change-master→get flow
- docs_readme: usage, threat model, tradeoffs
v1:
- change_master: re-wrap all entries; atomic temp DB + rename
- backoff: exponential sleep on unlock failures
- export_import: encrypted JSON bundle; roundtrip test
- info_cmd: print kdf params; health check (unique nonce scan optional)
- ci: github actions workflow for fmt, clippy -D warnings, tests
later:
- notes_flag: --notes for add/get
- clipboard: copy secret with auto-clear (warn about risks)
- session_agent: optional in-memory session unlock with explicit lock
- password_generator: length/charset options; entropy meter
- migration_system: sqlx migrate scripts; versioned schema
- packaging: release builds for major platforms

acceptance_criteria:
- init_creates_vault: vault.db exists; meta row present; no plaintext secrets on disk.
- aead_tamper_detected: altering nonce/ad/ciphertext leads to decrypt failure.
- unique_index: (service,username) collisions are rejected.
- zeroization: master pw, derived key, plaintext buffers are wrapped and dropped promptly.
- change_master_atomic: interruption does not corrupt the vault; entries readable after.
- tests_green: cargo test passes locally and in CI.

coding_guidelines:
- Prefer small, single-purpose functions; return anyhow::Result<T>.
- Use sqlx::query_as or FromRow entities; no stringly-typed column positions.
- Avoid .to_string() on secrets; prefer serde_json::to_writer into Zeroizing<Vec<u8>>.
- No println! of secrets; structured logs only for non-sensitive events.
- Deny clippy warnings in CI; run cargo fmt --check.

prompts_for_agent:
- "Generate cmd_get that unlocks, fetches Entry by (service, username), AEAD-decrypts with AD, and prints only the password. Use zeroizing buffers."
- "Implement change_master using a temp file migration: create new DB, copy rows re-encrypting with new salt+key, then replace old file atomically."
- "Write unit tests for derive_key determinism and AEAD tamper detection."
- "Refactor ad_for(service, username) to use length-prefix encoding and add a test."
- "Create README.md sections: Quickstart, Security Model, Threat Model, FAQs."

ci_pipeline/local pre-commit checks:
tools:
- cargo fmt --all -- --check
- cargo clippy --all-targets -- -D warnings
- cargo test --all
cache: true
os: ubuntu-latest

risk_register:
- id: nonces_reuse
  desc: Nonce reuse with same key is catastrophic.
  mitigation: always random 24B nonce; test uniqueness across inserts.
- id: logging_secrets
  desc: Accidental logging of plaintext or keys.
  mitigation: structured logs only; code review checklist; grep in CI.
- id: weak_kdf_params
  desc: Too-low Argon2 params reduce brute-force cost.
  mitigation: store params; expose info; document recommended tuning.
- id: partial_rewrap_failure
  desc: Crash during change-master could leave vault inconsistent.
  mitigation: temp DB + rename; verify counts; recover on startup if temp found.

glossary:
AEAD: "Authenticated Encryption with Associated Data; encrypt+integrity."
KDF: "Key Derivation Function; hardens a password into a symmetric key."
Salt: "Random, per-vault bytes used in KDF; public."
Nonce: "Random, per-encryption unique value; public, never reused."
AD: "Associated Data; plaintext metadata authenticated with the ciphertext."

ready_checklist:
- deps added to Cargo.toml
- ensure_schema implemented and checked
- Meta/Entry entities created with FromRow
- init/add/get wired and passing unit tests
- ci workflow added; clippy + fmt clean
