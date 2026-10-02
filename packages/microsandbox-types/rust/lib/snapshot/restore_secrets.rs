//! Captured secret descriptors and TLS interception state needed to restore a
//! snapshot whose source sandbox used `--secret ENV@HOST`.
//!
//! Only descriptors are captured — never secret values. A restored sandbox's
//! guest environment already carries the placeholder from before the
//! snapshot, so the descriptor (env var, placeholder, allowed hosts,
//! substitution policy, ...) is exactly what restore needs to rebuild the
//! same TLS-intercepting substitution behavior. The actual value is supplied
//! again by the caller at restore time (e.g. `--secret ENV@HOST`, resolved
//! host-side from the environment at spawn), or the secret is dropped.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};
use crate::{HostPattern, SecretEntry, SecretSubstitution, SecretViolationAction, TlsConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand key for the secret descriptors and TLS state retained by a snapshot.
pub const RESTORE_SECRETS_EXTENSION: &str = "microsandbox.restore-secrets";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Everything restore needs to rebuild the source sandbox's secret
/// substitution and TLS interception state, without ever carrying a value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSecretsPayload {
    /// Descriptors for every secret configured on the source sandbox, in
    /// source order. Never contains a value.
    #[serde(default)]
    pub secrets: Vec<RestoreSecretDescriptor>,

    /// Source sandbox's default hosts allowed to receive placeholders unchanged.
    #[serde(default)]
    pub passthrough_hosts: Option<Vec<HostPattern>>,

    /// Source sandbox's default action on a placeholder leaking to a disallowed host.
    #[serde(default)]
    pub violation_action: SecretViolationAction,

    /// Source sandbox's TLS interception configuration. Holds only flags and
    /// host-side certificate paths, never key material, so reapplying it at
    /// restore reconstructs the same interception CA the guest already trusts.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// One captured secret, mirroring [`SecretEntry`] minus its value and host-side source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSecretDescriptor {
    /// Environment variable name exposed to the sandbox.
    pub env_var: String,

    /// Placeholder string the sandbox saw instead of the real value.
    pub placeholder: String,

    /// Hosts allowed to receive the substituted secret value.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Request locations where the placeholder could be substituted.
    #[serde(default)]
    pub substitution: SecretSubstitution,

    /// Hosts allowed to receive the placeholder unchanged.
    #[serde(default)]
    pub passthrough_hosts: Vec<HostPattern>,

    /// Action on a violation for this secret (overrides the config default).
    #[serde(default)]
    pub violation_action: Option<SecretViolationAction>,

    /// Whether verified TLS identity was required before substitution.
    #[serde(default)]
    pub require_tls_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record captured secret descriptors and TLS state without ever embedding a value.
    ///
    /// Absence (an empty payload, i.e. no captured secrets) preserves the
    /// released descriptor's bytes exactly, so snapshots of sandboxes without
    /// secrets stay unaffected. Any captured secret makes the extension
    /// required: an older reader must refuse rather than silently restore
    /// without the source's TLS interception and substitution state.
    pub fn set_restore_secrets(
        &mut self,
        secrets: RestoreSecretsPayload,
    ) -> SnapshotManifestResult<()> {
        validate_restore_secrets(&secrets)?;
        if secrets.secrets.is_empty() {
            self.extensions.remove(RESTORE_SECRETS_EXTENSION);
            self.requires.retain(|key| key != RESTORE_SECRETS_EXTENSION);
            return Ok(());
        }
        self.extensions.insert(
            RESTORE_SECRETS_EXTENSION.into(),
            serde_json::to_value(secrets)
                .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?,
        );
        self.requires.push(RESTORE_SECRETS_EXTENSION.into());
        self.requires.sort();
        self.requires.dedup();
        Ok(())
    }

    /// Read and validate the captured secret descriptors; `None` when the
    /// source sandbox had no secrets (including all snapshots predating this
    /// extension).
    pub fn restore_secrets(&self) -> SnapshotManifestResult<Option<RestoreSecretsPayload>> {
        let Some(value) = self.extensions.get(RESTORE_SECRETS_EXTENSION) else {
            return Ok(None);
        };
        if !self
            .requires
            .iter()
            .any(|key| key == RESTORE_SECRETS_EXTENSION)
        {
            return invalid("restore secrets must be a required snapshot extension");
        }
        let secrets: RestoreSecretsPayload =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid restore secrets: {error}"))
            })?;
        validate_restore_secrets(&secrets)?;
        Ok(Some(secrets))
    }
}

impl RestoreSecretDescriptor {
    /// Capture a descriptor from a live secret entry, dropping its value and host-side source.
    pub fn from_entry(entry: &SecretEntry) -> Self {
        Self {
            env_var: entry.env_var.clone(),
            placeholder: entry.placeholder.clone(),
            allowed_hosts: entry.allowed_hosts.clone(),
            substitution: entry.substitution.clone(),
            passthrough_hosts: entry.passthrough_hosts.clone(),
            violation_action: entry.violation_action.clone(),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_restore_secrets(secrets: &RestoreSecretsPayload) -> SnapshotManifestResult<()> {
    if secrets.secrets.len() > 256 {
        return invalid("restore secret count exceeds the format bound");
    }
    let mut env_vars = std::collections::BTreeSet::new();
    for descriptor in &secrets.secrets {
        if descriptor.env_var.is_empty() || descriptor.env_var.contains(['=', '\0']) {
            return invalid("restore secret has an invalid env_var");
        }
        if !env_vars.insert(descriptor.env_var.as_str()) {
            return invalid("restore secret env_var is not unique");
        }
        if descriptor.placeholder.is_empty()
            || descriptor.placeholder.len() > crate::MAX_SECRET_PLACEHOLDER_BYTES
            || descriptor.placeholder.contains(['\0', '\r', '\n'])
        {
            return invalid("restore secret has an invalid placeholder");
        }
    }
    Ok(())
}

fn invalid<T>(message: &str) -> SnapshotManifestResult<T> {
    Err(SnapshotManifestError::ManifestParse(message.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(env_var: &str, value: &str) -> SecretEntry {
        SecretEntry {
            env_var: env_var.into(),
            value: value.to_string().into(),
            source: None,
            placeholder: format!("{{{{{env_var}}}}}"),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: SecretSubstitution {
                headers: true,
                query: false,
                body: false,
            },
            passthrough_hosts: Vec::new(),
            violation_action: Some(SecretViolationAction::Block),
            require_tls_identity: true,
        }
    }

    #[test]
    fn from_entry_drops_value_and_source() {
        let source = entry("API_KEY", "super-secret-value-123");
        let descriptor = RestoreSecretDescriptor::from_entry(&source);
        assert_eq!(descriptor.env_var, "API_KEY");
        assert_eq!(descriptor.placeholder, source.placeholder);
        assert_eq!(descriptor.allowed_hosts, source.allowed_hosts);
        assert_eq!(descriptor.require_tls_identity, source.require_tls_identity);
    }

    #[test]
    fn no_secret_values_are_ever_serialized() {
        let source = entry("API_KEY", "super-secret-value-123");
        let payload = RestoreSecretsPayload {
            secrets: vec![RestoreSecretDescriptor::from_entry(&source)],
            passthrough_hosts: None,
            violation_action: SecretViolationAction::BlockAndLog,
            tls: TlsConfig::default(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("super-secret-value-123"));

        let value = serde_json::to_value(&payload).unwrap();
        let first = &value["secrets"][0];
        assert!(
            first.as_object().unwrap().get("value").is_none(),
            "descriptor must never carry a `value` key: {first}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_env_vars() {
        let payload = RestoreSecretsPayload {
            secrets: vec![
                RestoreSecretDescriptor::from_entry(&entry("API_KEY", "a")),
                RestoreSecretDescriptor::from_entry(&entry("API_KEY", "b")),
            ],
            ..Default::default()
        };
        assert!(validate_restore_secrets(&payload).is_err());
    }

    #[test]
    fn validate_rejects_empty_env_var_and_placeholder() {
        let mut descriptor = RestoreSecretDescriptor::from_entry(&entry("API_KEY", "a"));
        descriptor.env_var = String::new();
        let payload = RestoreSecretsPayload {
            secrets: vec![descriptor],
            ..Default::default()
        };
        assert!(validate_restore_secrets(&payload).is_err());

        let mut descriptor = RestoreSecretDescriptor::from_entry(&entry("API_KEY", "a"));
        descriptor.placeholder = String::new();
        let payload = RestoreSecretsPayload {
            secrets: vec![descriptor],
            ..Default::default()
        };
        assert!(validate_restore_secrets(&payload).is_err());
    }
}
