//! Seeds a throwaway vault so the PoC can be tried without touching a real one.
//!
//! ```bash
//! mkdir -p /tmp/zann-demo
//! export ZANN_DB_URL=sqlite:///tmp/zann-demo/local.sqlite
//! export ZANN_DEMO_PASSWORD=pick-your-own
//! cargo run --example seed_demo_vault
//! cargo run
//! ```
//!
//! The identity config lands next to the database file, so point `ZANN_DB_URL`
//! at a directory of its own. Both variables are required: this creates a real
//! vault, and a vault whose master password ships in the repository is not one.

use zann_ffi::{create_core, ItemUpdate};

const DEMO_ITEMS: &[(&str, &str, &str)] = &[
    ("work/aws/root", "access_key", "AKIA0000000000000000"),
    ("work/aws/ci", "token", "ci-token-value"),
    ("work/grafana", "api_key", "grafana-key"),
    ("personal/router", "admin", "router-admin"),
    ("scratch", "note", "nothing to see here"),
];

/// A login with a masked password and a one-time code, so the detail column has
/// something to hide and something to count down.
const DEMO_LOGIN: &str = r#"{
  "v": 1,
  "typeId": "login",
  "fields": {
    "username": { "kind": "text", "value": "demo@example.com" },
    "password": { "kind": "password", "value": "correct-horse-battery-staple" },
    "url": { "kind": "url", "value": "https://mail.example.com" },
    "otp": { "kind": "otp", "value": "JBSWY3DPEHPK3PXP" },
    "notes": { "kind": "note", "value": "Recovery codes are in the safe." }
  }
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = std::env::var("ZANN_DB_URL")
        .map_err(|_| "set ZANN_DB_URL to a sqlite:// path in a directory of its own")?;
    let password = std::env::var("ZANN_DEMO_PASSWORD")
        .map_err(|_| "set ZANN_DEMO_PASSWORD to the master password for the demo vault")?;

    let core = create_core(db_url.clone())?;
    if core.app_status()?.initialized {
        core.unlock(password)?;
        println!("{db_url} already initialized, adding items to the existing vault");
    } else {
        core.initialize_master_password(password)?;
        println!("initialized {db_url}");
    }

    for (path, key, value) in DEMO_ITEMS {
        core.debug_create_kv_item(path.to_string(), key.to_string(), value.to_string())?;
    }

    // The facade only creates key/value items directly, so the login is created
    // as one and then rewritten with the payload above.
    let id = core.debug_create_kv_item(
        "personal/mail".to_string(),
        "placeholder".to_string(),
        String::new(),
    )?;
    core.item_update(
        id,
        ItemUpdate {
            title: "mail".to_string(),
            path: "personal/mail".to_string(),
            type_id: "login".to_string(),
            payload_json: DEMO_LOGIN.to_string(),
        },
    )?;

    println!("seeded {} items and one login", DEMO_ITEMS.len());
    Ok(())
}
