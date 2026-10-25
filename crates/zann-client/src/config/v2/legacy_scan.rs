use super::*;

pub(super) fn normalize_address(address: &str, path: &str) -> Result<String, ConfigError> {
    let mut parsed = Url::parse(address).map_err(|error| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: format!("invalid server URL: {error}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL scheme must be http or https".to_string(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must not contain userinfo".to_string(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must not contain a query or fragment".to_string(),
        });
    }
    if parsed.host().is_none() || parsed.cannot_be_a_base() {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "server URL must have a network host".to_string(),
        });
    }
    if parsed.path().contains('%') {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "percent-encoded server URL paths are not supported".to_string(),
        });
    }
    let normalized_domain = match parsed.host() {
        Some(Host::Domain(domain)) if domain.ends_with('.') => {
            let domain = domain.strip_suffix('.').unwrap_or_default();
            if domain.is_empty() || domain.ends_with('.') {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "server URL has an invalid DNS trailing dot".to_string(),
                });
            }
            Some(domain.to_string())
        }
        _ => None,
    };
    if let Some(domain) = normalized_domain {
        parsed
            .set_host(Some(&domain))
            .map_err(|error| ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: format!("invalid normalized server host: {error}"),
            })?;
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

#[derive(Default)]
pub(super) struct LegacyUnknownFields {
    pub(super) deferred: BTreeSet<String>,
    pub(super) credential_profile: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) enum LegacyScanKind {
    Root,
    Contexts,
    Connection,
    Profiles,
    Profile,
    Identity,
    Storage,
}

#[derive(Clone)]
pub(super) struct LegacyScan {
    pub(super) kind: LegacyScanKind,
    pub(super) path: String,
    pub(super) fields: Rc<RefCell<LegacyUnknownFields>>,
}

impl LegacyScan {
    pub(super) fn child(&self, kind: LegacyScanKind, path: String) -> Self {
        Self {
            kind,
            path,
            fields: Rc::clone(&self.fields),
        }
    }

    pub(super) fn record_deferred<E: de::Error>(&self, path: String) -> Result<(), E> {
        let mut fields = self.fields.borrow_mut();
        if !fields.deferred.contains(&path) && fields.deferred.len() >= MAX_DEFERRED_FIELDS {
            return Err(de::Error::custom("legacy deferred-field budget exceeded"));
        }
        fields.deferred.insert(path);
        Ok(())
    }

    pub(super) fn record_credential_profile_unknown(&self, path: String) {
        let mut fields = self.fields.borrow_mut();
        if fields.credential_profile.is_none() {
            fields.credential_profile = Some(path);
        }
    }
}

impl<'de> DeserializeSeed<'de> for LegacyScan {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for LegacyScan {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("legacy JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(mut key) = map.next_key::<String>()? {
            match self.kind {
                LegacyScanKind::Root => match key.as_str() {
                    "contexts" => map.next_value_seed(
                        self.child(LegacyScanKind::Contexts, "$.contexts".to_string()),
                    )?,
                    "identity" => map.next_value_seed(
                        self.child(LegacyScanKind::Identity, "$.identity".to_string()),
                    )?,
                    "storage" => map.next_value_seed(
                        self.child(LegacyScanKind::Storage, "$.storage".to_string()),
                    )?,
                    "current_context" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Contexts => {
                    let path = checked_legacy_scan_path::<A::Error>(
                        &self.path,
                        &key,
                        MAX_LEGACY_NAME_LEN,
                    )?;
                    map.next_value_seed(self.child(LegacyScanKind::Connection, path))?
                }
                LegacyScanKind::Connection => match key.as_str() {
                    "tokens" => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_LEGACY_NAME_LEN,
                        )?;
                        map.next_value_seed(self.child(LegacyScanKind::Profiles, path))?
                    }
                    "addr"
                    | "needs_salt_update"
                    | "server_id"
                    | "server_fingerprint"
                    | "expected_master_key_fp"
                    | "current_token"
                    | "storage_id"
                    | "vault" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Profiles => {
                    let path = checked_legacy_scan_path::<A::Error>(
                        &self.path,
                        &key,
                        MAX_LEGACY_NAME_LEN,
                    )?;
                    map.next_value_seed(self.child(LegacyScanKind::Profile, path))?
                }
                LegacyScanKind::Profile => match key.as_str() {
                    "access_token"
                    | "refresh_token"
                    | "service_account_token"
                    | "access_expires_at" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        if self.fields.borrow().credential_profile.is_none() {
                            let path = checked_legacy_scan_path::<A::Error>(
                                &self.path,
                                &key,
                                MAX_DEFERRED_PATH_LEN,
                            )?;
                            self.record_credential_profile_unknown(path);
                        }
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Identity => match key.as_str() {
                    "kdf_salt" | "kdf_params" | "salt_fingerprint" | "first_seen_at" | "email" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
                LegacyScanKind::Storage => match key.as_str() {
                    "backup_dir" | "backup_retention_days" | "backup_max_count" => {
                        map.next_value::<IgnoredAny>()?;
                    }
                    _ => {
                        let path = checked_legacy_scan_path::<A::Error>(
                            &self.path,
                            &key,
                            MAX_DEFERRED_PATH_LEN,
                        )?;
                        self.record_deferred(path)?;
                        map.next_value::<IgnoredAny>()?;
                    }
                },
            }
            key.zeroize();
        }
        Ok(())
    }
}

pub(super) fn scan_legacy_unknown_fields(
    bytes: &[u8],
) -> Result<LegacyUnknownFields, serde_json::Error> {
    let fields = Rc::new(RefCell::new(LegacyUnknownFields::default()));
    let scan = LegacyScan {
        kind: LegacyScanKind::Root,
        path: "$".to_string(),
        fields: Rc::clone(&fields),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    scan.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Rc::try_unwrap(fields)
        .map(RefCell::into_inner)
        .map_err(|_| de::Error::custom("legacy scan retained internal state"))
}

pub(super) fn legacy_path(base: &str, segment: &str) -> String {
    let escaped = escape_legacy_path_segment(segment);
    if escaped.starts_with('[') {
        format!("{base}{escaped}")
    } else {
        format!("{base}.{escaped}")
    }
}

pub(super) fn checked_legacy_scan_path<E: de::Error>(
    base: &str,
    segment: &str,
    maximum_segment_len: usize,
) -> Result<String, E> {
    if segment.is_empty() || segment.len() > maximum_segment_len {
        return Err(de::Error::custom(
            "legacy JSON path segment is out of bounds",
        ));
    }
    let path = legacy_path(base, segment);
    if path.len() > MAX_DEFERRED_PATH_LEN {
        return Err(de::Error::custom(
            "legacy JSON path exceeds configured limit",
        ));
    }
    Ok(path)
}

pub(super) fn escape_legacy_path_segment(segment: &str) -> String {
    if segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        segment.to_string()
    } else {
        format!("['{}']", segment.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

pub(super) fn validate_legacy_references(legacy: &LegacyConfig) -> Result<(), ConfigError> {
    if let Some(current_context) = &legacy.current_context {
        if !legacy.contexts.contains_key(current_context) {
            return Err(ConfigError::InvalidConfig {
                path: "$.current_context".to_string(),
                reason: format!("context does not exist: {current_context}"),
            });
        }
    }
    for (connection_name, connection) in &legacy.contexts {
        if let Some(current_token) = &connection.current_token {
            if !connection.tokens.contains_key(current_token) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.contexts.{connection_name}.current_token"),
                    reason: format!("credential profile does not exist: {current_token}"),
                });
            }
        }
    }
    Ok(())
}
