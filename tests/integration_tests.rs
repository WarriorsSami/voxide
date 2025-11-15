use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pretty_assertions::assert_eq;
use rstest::rstest;
use std::fs;
use tempfile::TempDir;

/// Helper to create a temporary directory for test vaults
fn create_temp_dir() -> TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Helper to get the vault path in a temp directory
fn vault_path(temp_dir: &TempDir) -> String {
    temp_dir
        .path()
        .join("test_vault.db")
        .to_str()
        .unwrap()
        .to_string()
}

// ============================================================================
// Help and Version Tests
// ============================================================================

#[test]
fn test_cli_help() {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("password manager"))
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_version() {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("voxide"));
}

#[rstest]
#[case("init", "Creates a new encrypted vault")]
#[case("add", "Store a new password")]
#[case("get", "Decrypt and display")]
#[case("list", "Display all service/username")]
#[case("delete", "Permanently remove")]
#[case("change-master", "re-encrypt all entries")]
#[case("export", "encrypted JSON backup")]
#[case("import", "Restore entries")]
fn test_command_help(#[case] command: &str, #[case] expected_text: &str) {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg(command).arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_text));
}

// ============================================================================
// Nonexistent Vault Tests
// ============================================================================

#[rstest]
#[case("list", vec![], "voxide init")]
#[case("get", vec!["-s", "github", "-u", "user"], "does not exist")]
#[case("change-master", vec![], "voxide init")]
fn test_commands_on_nonexistent_vault(
    #[case] command: &str,
    #[case] extra_args: Vec<&str>,
    #[case] expected_error: &str,
) {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault").arg(&vault).arg(command);

    for arg in extra_args {
        cmd.arg(arg);
    }

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains(expected_error));
}

#[test]
fn test_delete_on_nonexistent_vault() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(&vault)
        .arg("delete")
        .arg("-s")
        .arg("service")
        .arg("-u")
        .arg("user")
        .write_stdin("yes\n");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_export_on_nonexistent_vault() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);
    let export_path = temp_dir.path().join("export.json");

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(&vault)
        .arg("export")
        .arg("-p")
        .arg(export_path.to_str().unwrap());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_import_nonexistent_file() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);
    let import_path = temp_dir.path().join("nonexistent.json");

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(&vault)
        .arg("import")
        .arg("-p")
        .arg(import_path.to_str().unwrap());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}


// ============================================================================
// File System and Path Tests
// ============================================================================

#[test]
fn test_vault_file_does_not_exist_initially() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    // Vault should not exist initially
    assert_eq!(std::path::Path::new(&vault).exists(), false);
}

#[test]
fn test_export_file_already_exists() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);
    let export_path = temp_dir.path().join("existing.json");

    // Create an existing export file
    fs::write(&export_path, "existing content").expect("Failed to create test file");

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(&vault)
        .arg("export")
        .arg("-p")
        .arg(export_path.to_str().unwrap());

    cmd.assert().failure();
}

#[test]
fn test_vault_path_validation() {
    let invalid_path = "/nonexistent/directory/vault.db";

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(invalid_path)
        .arg("list");

    cmd.assert().failure();
}

// ============================================================================
// CLI Flag and Argument Tests
// ============================================================================

#[rstest]
#[case("-v", vec!["-s", "service", "-u", "user"], "add")]
#[case("--vault", vec!["-s", "github", "-u", "alice"], "get")]
fn test_short_and_long_vault_flags(
    #[case] vault_flag: &str,
    #[case] service_user_args: Vec<&str>,
    #[case] command: &str,
) {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg(vault_flag).arg(&vault).arg(command);

    for arg in service_user_args {
        cmd.arg(arg);
    }

    // Will fail because vault doesn't exist, but verifies flag parsing works
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_list_with_pattern_flag() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--vault")
        .arg(&vault)
        .arg("list")
        .arg("-p")
        .arg("github");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_invalid_command() {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("invalid-command");

    cmd.assert()
        .failure()
        .stderr(
            predicate::str::contains("unrecognized subcommand")
                .or(predicate::str::contains("unexpected argument")),
        );
}

#[rstest]
#[case("add", "required")]
#[case("get", "required")]
#[case("delete", "required")]
fn test_missing_required_args(#[case] command: &str, #[case] expected: &str) {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg(command);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(expected));
}

// ============================================================================
// Security Information Tests
// ============================================================================

#[test]
fn test_help_messages_quality() {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Argon2id"))
        .stdout(predicate::str::contains("XChaCha20-Poly1305"))
        .stdout(predicate::str::contains("AEAD"));
}

#[rstest]
#[case("Argon2id")]
#[case("XChaCha20-Poly1305")]
#[case("AEAD")]
#[case("encrypted locally")]
fn test_security_features_documented(#[case] feature: &str) {
    let mut cmd = cargo_bin_cmd!("cli");
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(feature));
}

