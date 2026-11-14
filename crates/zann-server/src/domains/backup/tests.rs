use super::*;
use serde_json::{json, Value};
use std::io::{Seek, SeekFrom, Write};

fn fixture() -> Value {
    json!({"version":1,"exported_at":"2026-11-14T00:00:00Z","scope":"shared","plaintext":true,
    "vaults":[{"id":"11111111-1111-4111-8111-111111111111","slug":"fixture","name":"Fixture","item_count":1,"items":[{
        "id":"22222222-2222-4222-8222-222222222222","path":"fixture","name":"fixture","type_id":"login","tags":["one"],"favorite":true,
        "payload":{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"private-sentinel"}}},
        "checksum":"a".repeat(64),"version":1,"deleted_at":null,"updated_at":"2026-11-14T00:00:00Z"
    }]}]})
}

fn prepare(text: &str) -> Result<reader::Prepared, BackupError> {
    let mut file = tempfile::tempfile().expect("private fixture");
    file.write_all(text.as_bytes()).expect("write fixture");
    file.seek(SeekFrom::Start(0)).expect("rewind fixture");
    reader::prepare(file)
}

#[test]
fn admits_arbitrary_header_order_and_preserves_escaped_values() {
    let mut value = fixture();
    value["vaults"][0]["items"][0]["payload"]["fields"]["password"]["value"] =
        json!("spaces\nquotes\" café 🔐");
    let mut ready = prepare(&value.to_string()).expect("valid fixture");
    assert_eq!(ready.items, 1);
    let (index, item): (usize, format::SharedExportItem) =
        serde_json::from_reader(&mut ready.spool).expect("staged record");
    assert_eq!(index, 0);
    assert_eq!(
        item.payload.fields["password"].value,
        "spaces\nquotes\" café 🔐"
    );
}

#[test]
fn rejects_duplicates_at_every_object_boundary_and_redacts_diagnostics() {
    let text = fixture().to_string();
    let cases = [
        text.replacen(
            "\"scope\":\"shared\"",
            "\"scope\":\"shared\",\"scope\":\"shared\"",
            1,
        ),
        text.replacen(
            "\"slug\":\"fixture\"",
            "\"slug\":\"fixture\",\"slug\":\"fixture\"",
            1,
        ),
        text.replacen(
            "\"favorite\":true",
            "\"favorite\":true,\"favorite\":false",
            1,
        ),
        text.replacen(
            "\"fields\":{",
            "\"fields\":{\"password\":{\"kind\":\"text\",\"value\":\"other\"},",
            1,
        ),
        text.replacen(
            "\"kind\":\"password\"",
            "\"kind\":\"password\",\"kind\":\"text\"",
            1,
        ),
        text.replacen("\"kind\":\"password\"", "\"kind\":\"private-sentinel\"", 1),
        text.replacen(
            "\"fields\":{",
            "\"extra\":{\"key\":\"one\",\"key\":\"two\"},\"fields\":{",
            1,
        ),
    ];
    for text in cases {
        let error = match prepare(&text) {
            Err(e) => e,
            Ok(_) => panic!("duplicate accepted"),
        };
        assert!(!format!("{error:?} {error}").contains("private-sentinel"));
    }
}

#[test]
fn rejects_bad_contracts_counts_and_duplicate_item_identities_before_restore() {
    let mutations: [fn(&mut Value); 10] = [
        |v| v["version"] = json!(2),
        |v| v["vaults"][0]["item_count"] = json!(2),
        |v| v["vaults"][0]["items"][0]["path"] = json!("../bad"),
        |v| v["vaults"][0]["items"][0]["payload"]["v"] = json!(2),
        |v| v["vaults"][0]["items"][0]["tags"] = json!([""]),
        |v| v["vaults"][0]["unknown"] = json!(true),
        |v| {
            v["vaults"][0]["items"][0]
                .as_object_mut()
                .expect("item")
                .remove("tags");
        },
        |v| {
            v["vaults"][0]["items"][0]
                .as_object_mut()
                .expect("item")
                .remove("deleted_at");
        },
        |v| {
            let item = v["vaults"][0]["items"][0].clone();
            v["vaults"][0]["items"]
                .as_array_mut()
                .expect("items")
                .push(item);
            v["vaults"][0]["item_count"] = json!(2)
        },
        |v| {
            let vault = v["vaults"][0].clone();
            v["vaults"].as_array_mut().expect("vaults").push(vault)
        },
    ];
    for mutate in mutations {
        let mut value = fixture();
        mutate(&mut value);
        assert!(prepare(&value.to_string()).is_err());
    }
    assert!(prepare(&(fixture().to_string() + "garbage")).is_err());
    assert!(prepare(&format!(
        "{{\"scope\":\"{}\"}}",
        "x".repeat(format::MAX_RECORD_BYTES + 1)
    ))
    .is_err());
}

#[test]
fn private_input_rejects_symlinks_hardlinks_and_public_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().expect("directory");
    let file = tempfile::NamedTempFile::new_in(dir.path()).expect("file");
    assert!(files::open_private(file.path()).is_ok());
    let link = dir.path().join("link");
    symlink(file.path(), &link).expect("symlink");
    assert!(files::open_private(&link).is_err());
    std::fs::hard_link(file.path(), dir.path().join("hard")).expect("hardlink");
    assert!(files::open_private(file.path()).is_err());
    std::fs::remove_file(dir.path().join("hard")).expect("unlink");
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    assert!(files::open_private(file.path()).is_err());
}
