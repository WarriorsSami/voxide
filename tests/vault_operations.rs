/// Programmatic vault operation tests
/// These tests use the vault service directly to avoid rpassword prompts
use secrecy::SecretString;
use tempfile::TempDir;
use voxide::domain::*;
use voxide::dto::*;
use voxide::vault::VaultService;

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

#[tokio::test]
async fn test_init_and_unlock() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("TestPassword123!".to_string().into_boxed_str());

    // Initialize vault
    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    let init_dto = InitVaultDto {
        master_password: master_password.clone(),
    };

    service.init(init_dto).await.expect("Failed to init vault");

    // Verify vault file was created
    assert!(std::path::Path::new(&vault).exists());

    // Verify we can unlock with correct password
    service
        .verify_unlock(&master_password)
        .await
        .expect("Failed to unlock vault");
}

#[tokio::test]
async fn test_init_twice_fails() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("TestPassword123!".to_string().into_boxed_str());

    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    let init_dto = InitVaultDto {
        master_password: master_password.clone(),
    };

    // First init should succeed
    service.init(init_dto).await.expect("Failed to init vault");

    // Second init should fail
    let init_dto2 = InitVaultDto {
        master_password: master_password.clone(),
    };
    let result = service.init(init_dto2).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_unlock_with_wrong_password() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let correct_password = SecretString::new("CorrectPassword123".to_string().into_boxed_str());
    let wrong_password = SecretString::new("WrongPassword456".to_string().into_boxed_str());

    // Initialize vault
    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: correct_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Try to unlock with wrong password
    let result = service.verify_unlock(&wrong_password).await;
    assert!(result.is_err());

    // Verify we can still unlock with correct password
    service
        .verify_unlock(&correct_password)
        .await
        .expect("Failed to unlock with correct password");
}

#[tokio::test]
async fn test_add_and_get_entry() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("MasterPass123".to_string().into_boxed_str());

    // Initialize vault
    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Add an entry
    let add_dto = AddEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("github".to_string()).unwrap(),
        username: Username::try_parse("alice@example.com".to_string()).unwrap(),
        password: Password::try_parse("SecretPassword123".to_string()).unwrap(),
        notes: Some(Notes::try_parse("Test notes".to_string()).unwrap()),
    };

    service.add(add_dto).await.expect("Failed to add entry");

    // Get the entry
    let get_dto = GetEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("github".to_string()).unwrap(),
        username: Username::try_parse("alice@example.com".to_string()).unwrap(),
    };

    let payload = service.get(get_dto).await.expect("Failed to get entry");

    assert_eq!(payload.password, "SecretPassword123");
    assert_eq!(payload.notes, Some("Test notes".to_string()));
}

#[tokio::test]
async fn test_add_duplicate_entry_fails() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("MasterPass123".to_string().into_boxed_str());

    let service_vault = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service_vault
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Add first entry
    let add_dto1 = AddEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("gitlab".to_string()).unwrap(),
        username: Username::try_parse("bob@test.com".to_string()).unwrap(),
        password: Password::try_parse("Password1".to_string()).unwrap(),
        notes: None,
    };

    service_vault
        .add(add_dto1)
        .await
        .expect("Failed to add first entry");

    // Try to add duplicate
    let add_dto2 = AddEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("gitlab".to_string()).unwrap(),
        username: Username::try_parse("bob@test.com".to_string()).unwrap(),
        password: Password::try_parse("Password2".to_string()).unwrap(),
        notes: None,
    };

    let result = service_vault.add(add_dto2).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_entries() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("MasterPass123".to_string().into_boxed_str());

    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // List should be empty initially
    let entries = service.list(None).await.expect("Failed to list entries");
    assert_eq!(entries.len(), 0);

    // Add entries
    service
        .add(AddEntryDto {
            master_password: master_password.clone(),
            service: Service::try_parse("github".to_string()).unwrap(),
            username: Username::try_parse("user1".to_string()).unwrap(),
            password: Password::try_parse("pass1".to_string()).unwrap(),
            notes: None,
        })
        .await
        .expect("Failed to add entry 1");

    service
        .add(AddEntryDto {
            master_password: master_password.clone(),
            service: Service::try_parse("gitlab".to_string()).unwrap(),
            username: Username::try_parse("user2".to_string()).unwrap(),
            password: Password::try_parse("pass2".to_string()).unwrap(),
            notes: None,
        })
        .await
        .expect("Failed to add entry 2");

    // List should now have 2 entries
    let entries = service.list(None).await.expect("Failed to list entries");
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn test_delete_entry() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("MasterPass123".to_string().into_boxed_str());

    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Add entry
    service
        .add(AddEntryDto {
            master_password: master_password.clone(),
            service: Service::try_parse("service1".to_string()).unwrap(),
            username: Username::try_parse("user1".to_string()).unwrap(),
            password: Password::try_parse("pass1".to_string()).unwrap(),
            notes: None,
        })
        .await
        .expect("Failed to add entry");

    // Delete entry
    let delete_dto = DeleteEntryDto {
        service: Service::try_parse("service1".to_string()).unwrap(),
        username: Username::try_parse("user1".to_string()).unwrap(),
    };

    service
        .delete(delete_dto)
        .await
        .expect("Failed to delete entry");

    // Entry should no longer exist
    let get_dto = GetEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("service1".to_string()).unwrap(),
        username: Username::try_parse("user1".to_string()).unwrap(),
    };

    let result = service.get(get_dto).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_nonexistent_entry_fails() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let master_password = SecretString::new("MasterPass123".to_string().into_boxed_str());

    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Try to delete non-existent entry
    let delete_dto = DeleteEntryDto {
        service: Service::try_parse("nonexistent".to_string()).unwrap(),
        username: Username::try_parse("nobody".to_string()).unwrap(),
    };

    let result = service.delete(delete_dto).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_change_master_password() {
    let temp_dir = create_temp_dir();
    let vault = vault_path(&temp_dir);

    let old_password = SecretString::new("OldPassword123".to_string().into_boxed_str());
    let new_password = SecretString::new("NewPassword456".to_string().into_boxed_str());

    // Initialize vault
    let service = VaultService::open(&vault)
        .await
        .expect("Failed to open vault");

    service
        .init(InitVaultDto {
            master_password: old_password.clone(),
        })
        .await
        .expect("Failed to init vault");

    // Add an entry
    service
        .add(AddEntryDto {
            master_password: old_password.clone(),
            service: Service::try_parse("test_service".to_string()).unwrap(),
            username: Username::try_parse("test_user".to_string()).unwrap(),
            password: Password::try_parse("test_password".to_string()).unwrap(),
            notes: None,
        })
        .await
        .expect("Failed to add entry");

    // Change master password
    let change_dto = ChangeMasterDto {
        old_password: old_password.clone(),
        new_password: new_password.clone(),
        vault_path: vault.clone(),
    };

    service
        .change_master(change_dto)
        .await
        .expect("Failed to change master password");

    // Open vault again with new password
    let service2 = VaultService::open(&vault)
        .await
        .expect("Failed to open vault after password change");

    // Old password should not work
    let result = service2.verify_unlock(&old_password).await;
    assert!(result.is_err());

    // New password should work
    service2
        .verify_unlock(&new_password)
        .await
        .expect("Failed to unlock with new password");

    // Entry should still be accessible with new password
    let get_dto = GetEntryDto {
        master_password: new_password.clone(),
        service: Service::try_parse("test_service".to_string()).unwrap(),
        username: Username::try_parse("test_user".to_string()).unwrap(),
    };

    let payload = service2.get(get_dto).await.expect("Failed to get entry");
    assert_eq!(payload.password, "test_password");
}

#[tokio::test]
async fn test_export_and_import() {
    let temp_dir = create_temp_dir();
    let vault1 = vault_path(&temp_dir);
    let vault2 = temp_dir
        .path()
        .join("vault2.db")
        .to_str()
        .unwrap()
        .to_string();
    let export_path = temp_dir
        .path()
        .join("export.json")
        .to_str()
        .unwrap()
        .to_string();

    let master_password = SecretString::new("ExportTestPass123".to_string().into_boxed_str());

    // Create and populate first vault
    let service1 = VaultService::open(&vault1)
        .await
        .expect("Failed to open vault1");

    service1
        .init(InitVaultDto {
            master_password: master_password.clone(),
        })
        .await
        .expect("Failed to init vault1");

    service1
        .add(AddEntryDto {
            master_password: master_password.clone(),
            service: Service::try_parse("export_test".to_string()).unwrap(),
            username: Username::try_parse("export_user".to_string()).unwrap(),
            password: Password::try_parse("export_pass".to_string()).unwrap(),
            notes: Some(Notes::try_parse("Export notes".to_string()).unwrap()),
        })
        .await
        .expect("Failed to add entry");

    // Export
    let export_dto = ExportVaultDto {
        master_password: master_password.clone(),
        export_path: export_path.clone(),
    };

    service1
        .export(export_dto)
        .await
        .expect("Failed to export vault");

    // Verify export file exists
    assert!(std::path::Path::new(&export_path).exists());

    // Import into second vault
    let service2 = VaultService::open(&vault2)
        .await
        .expect("Failed to open vault2");

    let import_dto = ImportVaultDto {
        master_password: master_password.clone(),
        import_path: export_path.clone(),
    };

    service2
        .import(import_dto)
        .await
        .expect("Failed to import vault");

    // Verify entry is in second vault
    let get_dto = GetEntryDto {
        master_password: master_password.clone(),
        service: Service::try_parse("export_test".to_string()).unwrap(),
        username: Username::try_parse("export_user".to_string()).unwrap(),
    };

    let payload = service2.get(get_dto).await.expect("Failed to get imported entry");
    assert_eq!(payload.password, "export_pass");
    assert_eq!(payload.notes, Some("Export notes".to_string()));
}

