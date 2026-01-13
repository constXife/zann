use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::modules::shared::{fetch_shared_items, payload_or_error};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn materialize_shared(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    prefix: Option<&str>,
    out: &Path,
    field: Option<&str>,
    skip_unchanged: bool,
    atomic: bool,
    limit: i64,
) -> anyhow::Result<()> {
    fs::create_dir_all(out)?;
    let mut cursor: Option<String> = None;
    loop {
        let response = fetch_shared_items(
            client,
            addr,
            access_token,
            vault_id,
            prefix,
            Some(limit),
            cursor.as_deref(),
        )
        .await?;
        for item in response.items {
            let payload = payload_or_error(&item)?;
            let rel = normalize_output_path(&item.path)?;
            let target = out.join(&rel);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let contents = if let Some(field) = field {
                let value = crate::find_field(payload, field).ok_or_else(|| {
                    anyhow::anyhow!("Field '{}' not found in {}", field, item.path)
                })?;
                value.value.clone()
            } else {
                serde_json::to_string_pretty(payload)?
            };
            if skip_unchanged && is_same_contents(&target, &contents)? {
                continue;
            }
            if atomic {
                write_atomic(&target, contents)?;
            } else {
                fs::write(&target, contents)?;
            }
        }
        cursor = response.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(())
}

pub(crate) fn read_template_source(path: &Path) -> anyhow::Result<String> {
    if path == Path::new("-") {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        return Ok(buffer);
    }
    Ok(fs::read_to_string(path)?)
}

pub(crate) fn write_render_output(out: Option<&Path>, contents: &str) -> anyhow::Result<()> {
    match out {
        None => {
            print!("{contents}");
            io::stdout().flush()?;
        }
        Some(path) if path == Path::new("-") => {
            print!("{contents}");
            io::stdout().flush()?;
        }
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(path, contents)?;
        }
    }
    Ok(())
}

fn is_same_contents(path: &Path, contents: &str) -> anyhow::Result<bool> {
    let existing = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    Ok(existing == contents.as_bytes())
}

fn write_atomic(path: &Path, contents: String) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid output path"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid output path"))?;
    let tmp_name = format!("{}.tmp.{}", file_name, rand::random::<u64>());
    let tmp_path = parent.join(tmp_name);
    fs::write(&tmp_path, contents)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

pub(crate) fn normalize_output_path(path: &str) -> anyhow::Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.starts_with('/') {
        return Err(anyhow::anyhow!("invalid path component: {}", path));
    }
    let trimmed = trimmed.trim_matches('/');
    let rel = Path::new(trimmed);
    for component in rel.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow::anyhow!("invalid path component: {}", path));
            }
        }
    }
    Ok(rel.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{materialize_shared, normalize_output_path};
    use mockito::Server;
    use serde_json::json;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn normalize_output_path_allows_simple() {
        let path = normalize_output_path("alpha/one").expect("valid path");
        assert_eq!(path, PathBuf::from("alpha/one"));
    }

    #[test]
    fn normalize_output_path_rejects_traversal() {
        assert!(normalize_output_path("../etc").is_err());
        assert!(normalize_output_path("foo/../bar").is_err());
        assert!(normalize_output_path("/etc").is_err());
    }

    #[tokio::test]
    async fn materialize_writes_files() {
        let mut server = Server::new_async().await;
        let vault_id = "vault-1";
        let list_body = json!({
            "items": [{
                "id": "00000000-0000-0000-0000-000000000001",
                "path": "alpha/one",
                "updated_at": "2024-01-01T00:00:00Z"
            }]
        });

        let list_mock = server
            .mock("GET", "/v1/vaults/vault-1/items")
            .with_status(200)
            .with_body(list_body.to_string())
            .create_async()
            .await;

        let item_body = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "path": "alpha/one",
            "payload": {
                "v": 1,
                "typeId": "kv",
                "fields": {
                    "password": {
                        "kind": "password",
                        "value": "secret"
                    }
                }
            }
        });
        let item_mock = server
            .mock(
                "GET",
                "/v1/vaults/vault-1/items/00000000-0000-0000-0000-000000000001",
            )
            .with_status(200)
            .with_body(item_body.to_string())
            .create_async()
            .await;

        let out_dir = tempdir().expect("tempdir");
        let client = reqwest::Client::new();
        materialize_shared(
            &client,
            &server.url(),
            "token",
            vault_id,
            None,
            out_dir.path(),
            Some("password"),
            false,
            true,
            200,
        )
        .await
        .expect("materialize ok");

        let target = out_dir.path().join("alpha/one");
        let contents = std::fs::read_to_string(target).expect("secret");
        assert_eq!(contents, "secret");
        list_mock.assert_async().await;
        item_mock.assert_async().await;
    }
}
