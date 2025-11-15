use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::path::Path;

use voxide::domain::*;
use voxide::dto::*;
use voxide::errors::VaultError;
use voxide::vault::VaultService;

/// Helper to display error messages with proper context
fn print_error(message: &str) {
    eprintln!("❌ Error: {}", message);
}

/// Helper to display success messages
fn print_success(message: &str) {
    println!("✓ {}", message);
}

/// Helper to display warnings
fn print_warning(message: &str) {
    eprintln!("⚠️ Warning: {}", message);
}

/// Validate password strength and provide feedback
fn validate_password_strength(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(anyhow!("Password cannot be empty"));
    }

    if password.len() < 8 {
        print_warning(
            "Master password is shorter than 8 characters. Consider using a longer password for better security.",
        );
    }

    Ok(())
}

/// Prompt for master password and unlock vault
async fn unlock_vault(vault_path: &str) -> Result<(VaultService, SecretString)> {
    // Check if vault file exists
    if !Path::new(vault_path).exists() {
        return Err(anyhow!(
            "Vault file '{}' does not exist.\n\n\
             Hint: Initialize a new vault first with:\n\
             voxide init",
            vault_path
        ));
    }

    let master_password = SecretString::new(
        rpassword::prompt_password("Master password: ")
            .context("Failed to read password from terminal")?
            .into_boxed_str(),
    );

    let vault_service = VaultService::open(vault_path)
        .await
        .context(format!("Failed to open vault at '{}'", vault_path))?;

    // Verify password by attempting to unlock
    vault_service
        .verify_unlock(&master_password)
        .await
        .map_err(|_| {
            anyhow!(
                "Authentication failed: Incorrect master password.\n\n\
                 The master password you entered does not match the vault.\n\
                 Please try again or check that you're using the correct vault file."
            )
        })?;

    Ok((vault_service, master_password))
}

#[derive(Parser)]
#[command(
    name = "voxide",
    version,
    about = "Encrypted password vault (SQLite + AEAD)",
    long_about = "A secure, encrypted password manager using SQLite and XChaCha20-Poly1305 AEAD.\n\
                  All data is encrypted locally with your master password.\n\n\
                  Security features:\n\
                  - Argon2id KDF for password derivation\n\
                  - XChaCha20-Poly1305 AEAD encryption\n\
                  - Unique nonce per entry\n\
                  - Authenticated encryption binding service/username"
)]
struct Cli {
    /// Path to the vault file (SQLite database)
    #[arg(
        short,
        long,
        global = true,
        default_value = "vault.db",
        value_name = "PATH",
        help = "Path to the vault file (SQLite database)"
    )]
    vault: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault with a master password
    #[command(long_about = "Creates a new encrypted vault database.\n\
                            You will be prompted to set a master password.\n\
                            This password cannot be recovered if forgotten.")]
    Init,

    /// Add a new password entry to the vault
    #[command(long_about = "Store a new password in the vault.\n\
                            Requires unlocking the vault with your master password.")]
    Add {
        /// Service or website name (e.g., 'github', 'gmail')
        #[arg(short, long, value_name = "SERVICE")]
        service: String,

        /// Username or email for this service
        #[arg(short, long, value_name = "USERNAME")]
        username: String,
    },

    /// Retrieve a password from the vault
    #[command(long_about = "Decrypt and display a stored password.\n\
                            The password will be shown in plain text on screen.")]
    Get {
        /// Service or website name (e.g., 'github', 'gmail')
        #[arg(short, long, value_name = "SERVICE")]
        service: String,

        /// Username or email for this service
        #[arg(short, long, value_name = "USERNAME")]
        username: String,
    },

    /// List all entries in the vault
    #[command(
        long_about = "Display all service/username pairs stored in the vault.\n\
                            Passwords are not shown, only metadata."
    )]
    List {
        #[arg(
            short,
            long,
            help = "Filter entries by service name or username (case-insensitive)"
        )]
        pattern: Option<String>,
    },

    /// Delete an entry from the vault
    #[command(long_about = "Permanently remove a password entry.\n\
                            This operation cannot be undone.")]
    Delete {
        /// Service or website name (e.g., 'github', 'gmail')
        #[arg(short, long, value_name = "SERVICE")]
        service: String,

        /// Username or email for this service
        #[arg(short, long, value_name = "USERNAME")]
        username: String,
    },

    /// Change the master password
    #[command(
        long_about = "Update your master password and re-encrypt all entries.\n\
                            This operation is atomic: if it fails, your vault remains unchanged."
    )]
    ChangeMaster,

    /// Export vault to an encrypted backup file
    #[command(long_about = "Create an encrypted JSON backup of your entire vault.\n\
                            The backup includes all entries in their encrypted form.")]
    Export {
        /// Path where the backup file will be saved
        #[arg(short, long, value_name = "PATH")]
        path: String,
    },

    /// Import vault from an encrypted backup file
    #[command(long_about = "Restore entries from an encrypted backup.\n\
                            The vault must be empty or newly initialized.")]
    Import {
        /// Path to the backup file to import
        #[arg(short, long, value_name = "PATH")]
        path: String,
    },
}

// TODO: Add docs explaining all the security considerations mentioned in the Copilot chat and not only
// TODO (nth): Add benchmarks/profiling (both time and memory footprint)
// TODO (nth): Expose the app also as a TUI (using Ratatui)
// TODO (nth): Add CI and pre-commit hooks
// TODO (nth): Add support for multiple vaults (e.g. for work/personal accounts)

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => cmd_init(&cli.vault).await,
        Commands::Add { service, username } => cmd_add(&cli.vault, service, username).await,
        Commands::Get { service, username } => cmd_get(&cli.vault, service, username).await,
        Commands::List { pattern } => cmd_list(&cli.vault, pattern).await,
        Commands::Delete { service, username } => cmd_delete(&cli.vault, service, username).await,
        Commands::ChangeMaster => cmd_change_master(&cli.vault).await,
        Commands::Export { path } => cmd_export(&cli.vault, path).await,
        Commands::Import { path } => cmd_import(&cli.vault, path).await,
    };

    if let Err(e) = result {
        print_error(&format!("{:#}", e));
        std::process::exit(1);
    }
}

async fn cmd_init(vault: &str) -> Result<()> {
    // Check if vault already exists
    if Path::new(vault).exists() {
        return Err(anyhow!(
            "Vault file '{}' already exists.\n\n\
             If you want to create a new vault, either:\n\
             1. Use a different file path with --vault <path>\n\
             2. Delete the existing vault (WARNING: This will lose all data)\n\
             3. Use 'change-master' to change the password of the existing vault",
            vault
        ));
    }

    println!("Creating new vault at: {}\n", vault);
    println!("⚠️  IMPORTANT: Your master password cannot be recovered if forgotten.");
    println!("    Choose a strong, memorable password.\n");

    let password = rpassword::prompt_password("Enter master password: ")
        .context("Failed to read password from terminal")?;

    validate_password_strength(&password)?;

    let password_confirm = rpassword::prompt_password("Confirm master password: ")
        .context("Failed to read password confirmation")?;

    if password != password_confirm {
        return Err(anyhow!(
            "Password mismatch: The passwords you entered do not match.\n\
             Please try again and ensure both passwords are identical."
        ));
    }

    let dto = InitVaultDto {
        master_password: SecretString::new(password.into_boxed_str()),
    };

    let service = VaultService::open(vault)
        .await
        .context(format!("Failed to create vault file at '{}'", vault))?;

    service
        .init(dto)
        .await
        .context("Failed to initialize vault")?;

    print_success(&format!("Vault initialized successfully at '{}'", vault));
    Ok(())
}

async fn cmd_add(vault: &str, service: String, username: String) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    let password_input =
        rpassword::prompt_password("Password to store: ").context("Failed to read password")?;

    if password_input.is_empty() {
        return Err(anyhow!("Password cannot be empty"));
    }

    println!("Notes (optional, press Enter to skip): ");
    let mut notes_input = String::new();
    std::io::stdin()
        .read_line(&mut notes_input)
        .context("Failed to read notes input")?;

    // Parse and validate domain types
    let service = Service::try_parse(service).context("Invalid service name")?;
    let username = Username::try_parse(username).context("Invalid username")?;
    let password = Password::try_parse(password_input).context("Invalid password")?;
    let notes = if notes_input.trim().is_empty() {
        None
    } else {
        Some(Notes::try_parse(notes_input.trim().to_string()).context("Invalid notes")?)
    };

    let dto = AddEntryDto {
        master_password,
        service: service.clone(),
        username: username.clone(),
        password,
        notes,
    };

    vault_service.add(dto).await.map_err(|e| {
        if matches!(e, VaultError::EntryExists) {
            anyhow!(
                "{}\n\
                 To update it, delete the old entry first with:\n\
                 voxide delete -s {} -u {}",
                e.user_message(),
                service,
                username
            )
        } else {
            anyhow!(e.user_message())
        }
    })?;

    print_success(&format!("Password added for {}/{}", service, username));
    Ok(())
}

async fn cmd_get(vault: &str, service: String, username: String) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    // Parse and validate domain types
    let service = Service::try_parse(service).context("Invalid service name")?;
    let username = Username::try_parse(username).context("Invalid username")?;

    let dto = GetEntryDto {
        master_password,
        service: service.clone(),
        username: username.clone(),
    };

    let payload = vault_service
        .get(dto)
        .await
        .map_err(|e| anyhow!(e.user_message()))?;

    println!("\n─────────────────────────────────");
    println!("Service:  {}", service);
    println!("Username: {}", username);
    println!("Password: {}", payload.password);
    if let Some(notes) = payload.notes {
        println!("Notes:    {}", notes);
    }
    println!("─────────────────────────────────\n");

    print_warning("The password is displayed in plain text above. Clear your screen when done.");

    Ok(())
}

async fn cmd_list(vault: &str, pattern: Option<String>) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, _master_password) = unlock_vault(vault).await?;

    let entries = vault_service
        .list(pattern)
        .await
        .context("Failed to retrieve entry list")?;

    if entries.is_empty() {
        println!("\nNo entries found in the vault.");
        println!("\nAdd your first password with:");
        println!("  voxide add -s <service> -u <username>\n");
        return Ok(());
    }

    println!("\n{:<30} {:<20} {}", "Service", "Username", "Created At");
    println!("{}", "─".repeat(80));
    for entry in &entries {
        println!(
            "{:<30} {:<20} {}",
            entry.service, entry.username, entry.created_at
        );
    }
    println!(
        "\nTotal: {} {}\n",
        entries.len(),
        if entries.len() == 1 {
            "entry"
        } else {
            "entries"
        }
    );

    Ok(())
}

async fn cmd_delete(vault: &str, service: String, username: String) -> Result<()> {
    // Parse and validate domain types first (before unlock for better UX)
    let service = Service::try_parse(service).context("Invalid service name")?;
    let username = Username::try_parse(username).context("Invalid username")?;

    println!(
        "⚠️  WARNING: This will permanently delete the entry for {}/{}",
        service, username
    );
    println!("This operation cannot be undone.\n");
    println!("Type 'yes' to confirm deletion: ");

    let mut confirm = String::new();
    std::io::stdin()
        .read_line(&mut confirm)
        .context("Failed to read confirmation")?;

    if confirm.trim().to_lowercase() != "yes" {
        println!("Deletion cancelled.");
        return Ok(());
    }

    // Unlock vault with master password (authorization required for deletion)
    let (vault_service, _master_password) = unlock_vault(vault).await?;

    let dto = DeleteEntryDto {
        service: service.clone(),
        username: username.clone(),
    };

    vault_service
        .delete(dto)
        .await
        .map_err(|e| anyhow!(e.user_message()))?;

    print_success(&format!("Deleted entry for {}/{}", service, username));
    Ok(())
}

async fn cmd_change_master(vault: &str) -> Result<()> {
    if !Path::new(vault).exists() {
        return Err(anyhow!(
            "Vault file '{}' does not exist.\n\n\
             Initialize a new vault first with:\n\
             voxide init",
            vault
        ));
    }

    println!("Changing master password for vault: {}\n", vault);
    println!("⚠️  This will re-encrypt all entries with a new password.");
    println!("    The operation is atomic: if it fails, your data remains safe.\n");

    let old_password = SecretString::new(
        rpassword::prompt_password("Current master password: ")
            .context("Failed to read current password")?
            .into_boxed_str(),
    );

    let new_password = rpassword::prompt_password("New master password: ")
        .context("Failed to read new password")?;

    validate_password_strength(&new_password)?;

    let new_password_secret = SecretString::new(new_password.clone().into_boxed_str());

    let new_password_confirm = rpassword::prompt_password("Confirm new master password: ")
        .context("Failed to read password confirmation")?;

    if new_password != new_password_confirm {
        return Err(anyhow!(
            "Password mismatch: The new passwords you entered do not match.\n\
             Please try again and ensure both passwords are identical."
        ));
    }

    let dto = ChangeMasterDto {
        old_password,
        new_password: new_password_secret,
        vault_path: vault.to_string(),
    };

    let vault_service = VaultService::open(vault)
        .await
        .context(format!("Failed to open vault at '{}'", vault))?;

    println!("\nRe-encrypting all entries...");

    vault_service.change_master(dto).await.map_err(|e| {
        anyhow!(
            "{}\n\nYour vault data remains secure and unchanged.",
            e.user_message()
        )
    })?;

    print_success("Master password changed successfully!");
    println!("\n⚠️  Important: You must use the new password for all future operations.");
    Ok(())
}

async fn cmd_export(vault: &str, path: String) -> Result<()> {
    // Check if export path already exists
    if Path::new(&path).exists() {
        return Err(anyhow!(
            "Export file '{}' already exists.\n\n\
             To avoid accidental overwrites, please:\n\
             1. Choose a different export path, or\n\
             2. Delete/rename the existing file first",
            path
        ));
    }

    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    let dto = ExportVaultDto {
        master_password,
        export_path: path.clone(),
    };

    println!("Exporting vault to: {}", path);

    vault_service
        .export(dto)
        .await
        .map_err(|e| anyhow!(e.user_message()))?;

    print_success(&format!("Vault exported successfully to '{}'", path));
    println!("\n⚠️  Keep this backup file secure - it contains your encrypted passwords.");
    Ok(())
}

async fn cmd_import(vault: &str, path: String) -> Result<()> {
    // Check if import file exists
    if !Path::new(&path).exists() {
        return Err(anyhow!(
            "Import file '{}' does not exist.\n\n\
             Please check the file path and try again.",
            path
        ));
    }

    // Check if vault already has data
    if Path::new(vault).exists() {
        return Err(anyhow!(
            "Vault file '{}' already exists.\n\n\
             Import can only be performed on a new, empty vault.\n\
             To import, either:\n\
             1. Use a different vault file with --vault <path>\n\
             2. Delete the existing vault (WARNING: This will lose all data)",
            vault
        ));
    }

    println!("Importing vault from: {}\n", path);
    println!("⚠️  You will need the master password from the backup.");

    // Prompt for the backup's master password
    let master_password = SecretString::new(
        rpassword::prompt_password("Master password (from backup): ")
            .context("Failed to read password")?
            .into_boxed_str(),
    );

    let dto = ImportVaultDto {
        master_password,
        import_path: path.clone(),
    };

    let vault_service = VaultService::open(vault)
        .await
        .context(format!("Failed to create vault file at '{}'", vault))?;

    vault_service.import(dto).await.map_err(|e| match e {
        VaultError::AuthFailed | VaultError::DecryptFailed => anyhow!(
            "Import failed: Incorrect password or corrupted backup file.\n\n\
             Please verify:\n\
             1. You're using the correct master password from the backup\n\
             2. The backup file is not corrupted\n\
             3. The backup file is a valid voxide export"
        ),
        other => anyhow!(other.user_message()),
    })?;

    print_success("Vault imported successfully!");
    Ok(())
}
