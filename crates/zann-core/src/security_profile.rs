use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SecurityProfilesFile {
    pub profiles: HashMap<String, SecurityProfile>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SecurityProfile {
    pub version: u32,
    #[serde(default)]
    pub ui: UiProfile,
    #[serde(default)]
    pub never_log_fields: Vec<String>,
    #[serde(default)]
    pub exposable_public_attrs: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct UiProfile {
    #[serde(default)]
    pub masked_by_default: Vec<String>,
    #[serde(default)]
    pub copyable: Vec<String>,
    #[serde(default)]
    pub revealable: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityProfileRegistry {
    profiles: HashMap<String, SecurityProfile>,
    masked_by_default: HashMap<String, HashSet<String>>,
}

impl SecurityProfileRegistry {
    pub fn from_yaml(contents: &str) -> Result<Self, serde_yaml::Error> {
        let file: SecurityProfilesFile = serde_yaml::from_str(contents)?;
        let mut masked_by_default = HashMap::new();
        for (type_id, profile) in &file.profiles {
            let mut set = HashSet::new();
            for field in &profile.ui.masked_by_default {
                set.insert(field.to_lowercase());
            }
            masked_by_default.insert(type_id.to_string(), set);
        }
        Ok(Self {
            profiles: file.profiles,
            masked_by_default,
        })
    }

    pub fn profile(&self, type_id: &str) -> Option<&SecurityProfile> {
        self.profiles.get(type_id)
    }

    pub fn profiles(&self) -> &HashMap<String, SecurityProfile> {
        &self.profiles
    }

    pub fn is_masked_by_default(&self, type_id: &str, field: &str) -> bool {
        let Some(set) = self.masked_by_default.get(type_id) else {
            return false;
        };
        let field_norm = field.trim().to_lowercase();
        if set.contains(&field_norm) {
            return true;
        }
        for entry in set {
            if let Some(prefix) = entry.strip_suffix(".*") {
                if field_norm.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }
}
