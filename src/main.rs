use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};

mod crypto;
mod db;
mod domain;
mod dto;
mod models;
mod vault;

use domain::*;
use dto::*;
use vault::VaultService;

/// Prompt for master password and unlock vault
async fn unlock_vault(vault_path: &str) -> Result<(VaultService, SecretString)> {
    let master_password =
        SecretString::new(rpassword::prompt_password("Master password: ")?.into_boxed_str());

    let vault_service = VaultService::open(vault_path).await?;

    // Verify password by attempting to unlock
    vault_service
        .verify_unlock(&master_password)
        .await
        .map_err(|e| anyhow!("Invalid master password: {}", e))?;

    Ok((vault_service, master_password))
}

#[derive(Parser)]
#[command(
    name = "voxide",
    version,
    about = "Encrypted password vault (SQLite + AEAD)"
)]
struct Cli {
    /// Path to the vault file (SQLite). Defaults to ./vault.db
    #[arg(long, global = true, default_value = "vault.db")]
    vault: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add { service: String, username: String },
    Get { service: String, username: String },
    List,
    Delete { service: String, username: String },
    ChangeMaster,
    Export { path: String },
    Import { path: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => cmd_init(&cli.vault).await?,
        Commands::Add { service, username } => cmd_add(&cli.vault, service, username).await?,
        Commands::Get { service, username } => cmd_get(&cli.vault, service, username).await?,
        Commands::List => cmd_list(&cli.vault).await?,
        Commands::Delete { service, username } => cmd_delete(&cli.vault, service, username).await?,
        Commands::ChangeMaster => cmd_change_master(&cli.vault).await?,
        Commands::Export { path } => cmd_export(&cli.vault, path).await?,
        Commands::Import { path } => cmd_import(&cli.vault, path).await?,
    }
    Ok(())
}

async fn cmd_init(vault: &str) -> Result<()> {
    let password = rpassword::prompt_password("Enter master password: ")?;
    let password_confirm = rpassword::prompt_password("Confirm master password: ")?;

    if password != password_confirm {
        anyhow::bail!("Passwords do not match");
    }

    let dto = InitVaultDto {
        master_password: SecretString::new(password.into_boxed_str()),
    };

    let service = VaultService::open(vault).await?;
    service.init(dto).await?;

    Ok(())
}

async fn cmd_add(vault: &str, service: String, username: String) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    let password_input = rpassword::prompt_password("Password to store: ")?;
    println!("Notes (optional, press Enter to skip): ");
    let mut notes_input = String::new();
    std::io::stdin().read_line(&mut notes_input)?;

    // Parse and validate domain types
    let service = Service::try_parse(service)?;
    let username = Username::try_parse(username)?;
    let password = Password::try_parse(password_input)?;
    let notes = if notes_input.trim().is_empty() {
        None
    } else {
        Some(Notes::try_parse(notes_input.trim().to_string())?)
    };

    let dto = AddEntryDto {
        master_password,
        service,
        username,
        password,
        notes,
    };

    vault_service.add(dto).await?;

    Ok(())
}

async fn cmd_get(vault: &str, service: String, username: String) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    // Parse and validate domain types
    let service = Service::try_parse(service)?;
    let username = Username::try_parse(username)?;

    let dto = GetEntryDto {
        master_password,
        service: service.clone(),
        username: username.clone(),
    };

    let payload = vault_service.get(dto).await?;

    println!("\n─────────────────────────────────");
    println!("Service:  {}", service);
    println!("Username: {}", username);
    println!("Password: {}", payload.password);
    if let Some(notes) = payload.notes {
        println!("Notes:    {}", notes);
    }
    println!("─────────────────────────────────\n");

    Ok(())
}

async fn cmd_list(vault: &str) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, _master_password) = unlock_vault(vault).await?;

    let entries = vault_service.list().await?;

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("\n{:<30} {:<20} {}", "Service", "Username", "Created At");
    println!("{}", "─".repeat(80));
    for entry in entries {
        println!(
            "{:<30} {:<20} {}",
            entry.service, entry.username, entry.created_at
        );
    }
    println!();

    Ok(())
}

async fn cmd_delete(vault: &str, service: String, username: String) -> Result<()> {
    // Parse and validate domain types
    let service = Service::try_parse(service)?;
    let username = Username::try_parse(username)?;

    println!("Delete entry for {}/{}? (yes/no): ", service, username);
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;

    if confirm.trim().to_lowercase() != "yes" {
        println!("Deletion cancelled.");
        return Ok(());
    }

    // Unlock vault with master password (authorization required for deletion)
    let (vault_service, _master_password) = unlock_vault(vault).await?;

    let dto = DeleteEntryDto { service, username };

    vault_service.delete(dto).await?;

    Ok(())
}

async fn cmd_change_master(vault: &str) -> Result<()> {
    let old_password = SecretString::new(
        rpassword::prompt_password("Current master password: ")?.into_boxed_str(),
    );
    let new_password =
        SecretString::new(rpassword::prompt_password("New master password: ")?.into_boxed_str());
    let new_password_confirm = SecretString::new(
        rpassword::prompt_password("Confirm new master password: ")?.into_boxed_str(),
    );

    if new_password.expose_secret() != new_password_confirm.expose_secret() {
        anyhow::bail!("New passwords do not match");
    }

    let dto = ChangeMasterDto {
        old_password,
        new_password,
        vault_path: vault.to_string(),
    };

    let vault_service = VaultService::open(vault).await?;
    vault_service.change_master(dto).await?;

    Ok(())
}

async fn cmd_export(vault: &str, path: String) -> Result<()> {
    // Unlock vault with master password
    let (vault_service, master_password) = unlock_vault(vault).await?;

    let dto = ExportVaultDto {
        master_password,
        export_path: path,
    };

    vault_service.export(dto).await?;

    Ok(())
}

async fn cmd_import(vault: &str, path: String) -> Result<()> {
    // Prompt for the backup's master password
    let master_password = SecretString::new(
        rpassword::prompt_password("Master password (from backup): ")?.into_boxed_str(),
    );

    let dto = ImportVaultDto {
        master_password,
        import_path: path,
    };

    let vault_service = VaultService::open(vault).await?;
    vault_service.import(dto).await?;

    Ok(())
}
