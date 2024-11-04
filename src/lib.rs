use anyhow::{Context, Result};
use azure_security_keyvault::SecretClient;
use std::collections::HashMap;

pub struct Vault {
    pub secrets: HashMap<String, String>,
}

pub trait VaultStorage {
    fn get_required(&self, key: &str) -> Result<String>;
}

impl Vault {
    /// Creates a Vault instance with Azure Key Vault secrets.
    ///
    /// # Arguments
    ///
    /// * `url` - URL
    ///
    /// # Returns
    ///
    /// A Result containing the Vault secrets if successful, or an error if the secrets
    /// could not be retrieved.
    ///
    /// # Example
    ///
    /// ```
    /// use rusty_psql::Vault;
    /// use anyhow::Result;
    ///
    /// async fn example() -> Result<()> {
    ///     let secret_keys = vec!["".to_string()];
    ///     let vault = Vault::new("AZURE_KEY_VAULT_TEST", secret_keys).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(url: &str, db_keys: Vec<String>) -> Result<Self> {
        let mut secrets = HashMap::new();

        let credential =
            azure_identity::create_credential().context("Failed to create credentials")?;
        let client = SecretClient::new(url, credential)
            .context("Failed to create a SecretClient instance")?;

        let keys_iter = db_keys.iter();
        for key in keys_iter {
            secrets.insert(key.clone(), get_secret(&client, key.clone()).await?);
        }

        Ok(Self { secrets })
    }
}

impl VaultStorage for Vault {
    /// Creates a VaultStorage instance.
    ///
    /// # Arguments
    ///
    /// * `self` - Vault
    /// * `key` - The Azure Key Vault secret
    ///
    /// # Returns
    ///
    /// A Result containing the Vault secrets if successful, or an error if the secrets
    /// could not be retrieved.
    ///
    /// # Example
    ///
    /// ```
    /// use rusty_psql::{Vault, VaultStorage};
    /// use anyhow::Result;
    ///
    /// async fn example() -> Result<()> {
    ///     let secret_keys = vec!["".to_string()];
    ///     let vault = Vault::new("AZURE_KEY_VAULT_TEST", secret_keys).await?;
    ///     let secret_key = VaultStorage::get_required(&vault, "")?;
    ///     Ok(())
    /// }
    /// ```
    fn get_required(&self, key: &str) -> Result<String> {
        self.secrets
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Required key '{}' not found", key))
    }
}

async fn get_secret(client: &SecretClient, key: String) -> Result<String> {
    let response = client.get(key).await.context("Unable to retrieve value")?;
    Ok(response.value.to_string())
}

#[cfg(test)]
mod tests {
    use db_config::DatabaseConfig;

    #[test]
    fn test_keys_returns_correct_number_of_fields() {
        let keys = DatabaseConfig::db_keys();
        assert_eq!(keys.len(), 5);
    }

    #[test]
    fn test_keys_have_correct_prefix() {
        let keys = DatabaseConfig::db_keys();
        for key in keys {
            assert!(key.starts_with("db-"));
        }
    }

    #[test]
    fn test_connection_string_format() {
        let config = DatabaseConfig {
            host: "myhost".to_string(),
            user: "myuser".to_string(),
            name: "mydb".to_string(),
            pwd: "mypass".to_string(),
            domain: "mydomain".to_string(),
        };

        assert_eq!(
            config.connection_string(),
            "postgres://myuser@myhost.mydomain/mydb"
        );
    }
}
