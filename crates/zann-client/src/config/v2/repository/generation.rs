use super::super::*;

impl ConfigRepository {
    /// Resolves a repository-bound, secret-free CAS anchor for a specific profile.
    ///
    /// Callers may use the credential ids to perform a network refresh, then submit the anchor to
    /// [`Self::replace_credential_bundle_if_profile_matches`]. Unrelated config mutations may
    /// advance the global revision while the network request is in flight.
    pub fn resolve_credential_profile_anchor(
        &self,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
    ) -> Result<CredentialProfileAnchor, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        let _lock = self.exclusive_lock()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes = read_file(&primary_path, "read config for profile anchor")?;
        let config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        resolve_credential_profile_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            byte_digest(&source_primary_bytes),
            &config,
            connection_id,
            &profile_name,
        )
    }

    /// Captures an authorization proof from the exact, unre-based source
    /// anchor used to read a stored credential.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn authorized_target_generation_from_anchor(
        &self,
        anchor: &CredentialProfileAnchor,
    ) -> Result<Arc<AuthorizedTargetGeneration>, ConfigError> {
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_sync_generation_recovery_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "authorize stored session generation")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        let source_digest = byte_digest(&primary_bytes);
        if config.revision != anchor.source_revision {
            return Err(ConfigError::RevisionConflict {
                expected: anchor.source_revision,
                actual: config.revision,
            });
        }
        if source_digest != anchor.source_digest {
            return Err(ConfigError::ConfigContentConflict {
                revision: anchor.source_revision,
            });
        }
        ensure_credential_profile_anchor_matches(
            anchor,
            &repository_binding,
            &config,
            &source_digest,
        )?;
        Ok(Arc::new(authorized_target_generation(
            repository_binding,
            source_digest,
            &primary_bytes,
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
        )?))
    }

    /// Captures an authorization proof from the exact config candidate
    /// returned by a credential transaction or its recovery.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn authorized_target_generation_from_snapshot(
        &self,
        snapshot: &ConfigSnapshot,
        connection_id: &ConnectionId,
        profile_name: &str,
    ) -> Result<Arc<AuthorizedTargetGeneration>, ConfigError> {
        let expected_bytes = serialize_config(snapshot.config())?;
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_sync_generation_recovery_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "authorize credential candidate generation")?;
        if primary_bytes != expected_bytes {
            let actual = parse_config(&primary_path, &primary_bytes)?;
            if actual.revision != snapshot.revision() {
                return Err(ConfigError::RevisionConflict {
                    expected: snapshot.revision(),
                    actual: actual.revision,
                });
            }
            return Err(ConfigError::ConfigContentConflict {
                revision: snapshot.revision(),
            });
        }
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        let source_digest = byte_digest(&primary_bytes);
        Ok(Arc::new(authorized_target_generation(
            repository_binding,
            source_digest,
            &primary_bytes,
            &config,
            connection_id,
            profile_name,
        )?))
    }

    /// Acquires the shared sync gate and validates an exact authorization
    /// generation under the config lock. The returned non-clone lease keeps
    /// config writers blocked while a local transaction commits.
    #[cfg(feature = "session")]
    pub async fn acquire_sync_commit_lease(
        &self,
        generation: &Arc<AuthorizedTargetGeneration>,
    ) -> Result<SyncCommitLease, ConfigError> {
        debug_assert!(lock_order_allows(LockKind::SyncCommit, LockKind::Config));
        let sync_commit = LockKind::SyncCommit
            .pending_at(self.paths.root())?
            .acquire_async(LOCK_TIMEOUT)
            .await?;
        let config_lock = match LockKind::Config
            .pending_at(self.paths.root())?
            .acquire_async(LOCK_TIMEOUT)
            .await
        {
            Ok(lock) => lock,
            Err(error) => {
                drop(sync_commit);
                return Err(error);
            }
        };

        let validation = (|| {
            self.ensure_no_pending_sync_generation_recovery_locked()?;
            let primary_path = self.paths.config();
            let primary_bytes = read_file(&primary_path, "validate sync commit generation")?;
            let config = parse_config(&primary_path, &primary_bytes)?;
            self.ensure_legacy_unchanged(&config)?;
            let repository_binding =
                credential_profile_anchor_repository_binding(self.paths.root())?;
            if repository_binding != generation.repository_binding_digest {
                return Err(ConfigError::CredentialProfileAnchorRepositoryMismatch);
            }
            if config.revision != generation.revision() {
                return Err(ConfigError::RevisionConflict {
                    expected: generation.revision(),
                    actual: config.revision,
                });
            }
            let source_digest = byte_digest(&primary_bytes);
            if source_digest != generation.source_digest {
                return Err(ConfigError::ConfigContentConflict {
                    revision: generation.revision(),
                });
            }
            let current = authorized_target_generation(
                repository_binding,
                source_digest,
                &primary_bytes,
                &config,
                &generation.connection_id,
                &generation.profile_name,
            )?;
            if current != **generation {
                return Err(ConfigError::CredentialProfileAnchorConflict {
                    connection_id: generation.connection_id.clone(),
                    profile_name: generation.profile_name.clone(),
                    field: "authorized_generation",
                });
            }
            self.ensure_no_pending_sync_generation_recovery_locked()
        })();
        drop(config_lock);
        if let Err(error) = validation {
            drop(sync_commit);
            return Err(error);
        }
        Ok(SyncCommitLease {
            generation: Arc::clone(generation),
            _sync_commit: sync_commit,
        })
    }

    /// Binds the anchored connection to one exact local master-key fingerprint.
    ///
    /// This is a metadata-only compare-and-swap. It performs no credential-store or network
    /// operation, rebases over unrelated higher revisions, and refuses to replace any existing
    /// different binding. A caller that intentionally changes master keys must use a separate,
    /// explicit rebind/reset workflow.
    pub fn bind_expected_master_key_fingerprint_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        target_fp: impl Into<String>,
    ) -> Result<MasterKeyFingerprintBindingOutcome, ConfigError> {
        let target_fp = target_fp.into();
        validate_master_key_fingerprint(&target_fp)?;

        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes =
            read_file(&primary_path, "read config for master-key fingerprint bind")?;
        let mut config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        ensure_credential_profile_anchor_matches(
            anchor,
            &credential_profile_anchor_repository_binding(self.paths.root())?,
            &config,
            &byte_digest(&source_primary_bytes),
        )?;
        if !anchor.master_key_binding_observed {
            return Err(credential_profile_anchor_conflict(
                anchor,
                "expected_master_key_fp",
            ));
        }

        let current_fp = config
            .connections
            .get(&anchor.connection_id)
            .ok_or_else(|| credential_profile_anchor_conflict(anchor, "connection"))?
            .metadata
            .expected_master_key_fp
            .clone();
        if current_fp != anchor.expected_master_key_fp {
            return Err(credential_profile_anchor_conflict(
                anchor,
                "expected_master_key_fp",
            ));
        }

        match current_fp {
            Some(current) if current == target_fp => Ok(
                MasterKeyFingerprintBindingOutcome::AlreadyBound(ConfigSnapshot { config }),
            ),
            Some(_) => Err(ConfigError::MasterKeyFingerprintRebindRequired {
                connection_id: anchor.connection_id.clone(),
            }),
            None => {
                config
                    .connections
                    .get_mut(&anchor.connection_id)
                    .expect("anchored connection was checked above")
                    .metadata
                    .expected_master_key_fp = Some(target_fp);
                config.revision = config
                    .revision
                    .checked_add(1)
                    .ok_or(ConfigError::RevisionOverflow)?;
                let candidate_bytes = serialize_config(&config)?;
                atomic_write(&self.paths.backup(), &source_primary_bytes)?;
                atomic_write(&primary_path, &candidate_bytes)?;
                Ok(MasterKeyFingerprintBindingOutcome::Bound(ConfigSnapshot {
                    config,
                }))
            }
        }
    }
}
