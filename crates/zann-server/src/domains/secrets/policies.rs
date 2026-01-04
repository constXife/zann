use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DEFAULT_POLICY_NAME: &str = "default";
const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub length: usize,
    #[serde(default)]
    pub min_lowercase: usize,
    #[serde(default)]
    pub min_uppercase: usize,
    #[serde(default)]
    pub min_digits: usize,
    #[serde(default)]
    pub min_symbols: usize,
    #[serde(default)]
    pub symbols: Option<String>,
}

impl PasswordPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.length == 0 {
            return Err("policy_length_zero");
        }
        let min_total = self
            .min_lowercase
            .saturating_add(self.min_uppercase)
            .saturating_add(self.min_digits)
            .saturating_add(self.min_symbols);
        if min_total > self.length {
            return Err("policy_min_exceeds_length");
        }
        if self.min_symbols > 0 {
            let symbols = self.symbols.as_deref().unwrap_or(DEFAULT_SYMBOLS);
            if symbols.trim().is_empty() {
                return Err("policy_symbols_empty");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPoliciesFile {
    #[serde(default)]
    pub default_policy: Option<String>,
    #[serde(default)]
    pub policies: HashMap<String, PasswordPolicy>,
}

pub fn default_policy_name() -> &'static str {
    DEFAULT_POLICY_NAME
}

pub fn default_policy() -> PasswordPolicy {
    PasswordPolicy {
        length: 32,
        min_lowercase: 1,
        min_uppercase: 1,
        min_digits: 1,
        min_symbols: 1,
        symbols: Some(DEFAULT_SYMBOLS.to_string()),
    }
}

pub fn generate_secret(policy: &PasswordPolicy) -> Result<String, &'static str> {
    policy.validate()?;

    let lowercase: Vec<char> = ('a'..='z').collect();
    let uppercase: Vec<char> = ('A'..='Z').collect();
    let digits: Vec<char> = ('0'..='9').collect();
    let symbol_set = policy.symbols.as_deref().unwrap_or(DEFAULT_SYMBOLS);
    let symbols: Vec<char> = symbol_set.chars().collect();

    let mut rng = rand::thread_rng();
    let mut result: Vec<char> = Vec::with_capacity(policy.length);

    for _ in 0..policy.min_lowercase {
        result.push(*lowercase.choose(&mut rng).ok_or("policy_lowercase_empty")?);
    }
    for _ in 0..policy.min_uppercase {
        result.push(*uppercase.choose(&mut rng).ok_or("policy_uppercase_empty")?);
    }
    for _ in 0..policy.min_digits {
        result.push(*digits.choose(&mut rng).ok_or("policy_digits_empty")?);
    }
    for _ in 0..policy.min_symbols {
        result.push(*symbols.choose(&mut rng).ok_or("policy_symbols_empty")?);
    }

    let mut pool = Vec::new();
    if policy.min_lowercase > 0 {
        pool.extend(lowercase);
    }
    if policy.min_uppercase > 0 {
        pool.extend(uppercase);
    }
    if policy.min_digits > 0 {
        pool.extend(digits);
    }
    if policy.min_symbols > 0 {
        pool.extend(symbols);
    }
    if pool.is_empty() {
        return Err("policy_empty_charset");
    }

    while result.len() < policy.length {
        let idx = rng.gen_range(0..pool.len());
        result.push(pool[idx]);
    }

    result.shuffle(&mut rng);
    Ok(result.into_iter().collect())
}
