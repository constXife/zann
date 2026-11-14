//! Validate the entire source before any DB writes; retain only bounded keys
//! and vault headers. Payloads stream into a private anonymous staging file.
use super::{format::*, BackupError};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use std::{
    cell::Cell,
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    rc::Rc,
};

pub(super) struct Prepared {
    pub vaults: Vec<SharedExportVault>,
    pub items: usize,
    pub spool: File,
}

struct State {
    spool: File,
    vaults: Vec<SharedExportVault>,
    ids: HashSet<uuid::Uuid>,
    paths: HashSet<(usize, String)>,
    remaining: Rc<Cell<usize>>,
    staging_error: Option<BackupError>,
}

impl State {
    fn stage(&mut self, vault: usize, item: SharedExportItem) -> Result<(), BackupError> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&(vault, item))?);
        self.spool.write_all(&bytes)?;
        self.spool.write_all(b"\n")?;
        Ok(())
    }
}

struct Limited<R> {
    inner: R,
    remaining: Rc<Cell<usize>>,
}
impl<R: Read> Read for Limited<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let n = bytes.len().min(self.remaining.get());
        if n == 0 {
            return Err(std::io::Error::other("backup record exceeds byte limit"));
        }
        let read = self.inner.read(&mut bytes[..n])?;
        self.remaining.set(self.remaining.get() - read);
        Ok(read)
    }
}

pub(super) fn prepare(file: File) -> Result<Prepared, BackupError> {
    prepare_into(file, tempfile::tempfile()?)
}

fn prepare_into(file: File, spool: File) -> Result<Prepared, BackupError> {
    let remaining = Rc::new(Cell::new(MAX_RECORD_BYTES));
    let mut state = State {
        spool,
        vaults: Vec::new(),
        ids: HashSet::new(),
        paths: HashSet::new(),
        remaining: remaining.clone(),
        staging_error: None,
    };
    let reader = Limited {
        inner: std::io::BufReader::new(file),
        remaining,
    };
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let admitted = Root(&mut state).deserialize(&mut deserializer);
    // Serde's generic visitor error cannot carry our typed I/O/source chain.
    // Keep that failure separately instead of flattening it to a JSON string.
    if let Some(error) = state.staging_error.take() {
        return Err(error);
    }
    admitted?;
    state.remaining.set(MAX_RECORD_BYTES);
    deserializer.end()?;
    let mut vault_ids = HashSet::new();
    let mut slugs = HashSet::new();
    for vault in &state.vaults {
        if !vault_ids.insert(validate_vault(vault)?) || !slugs.insert(&vault.slug) {
            return Err(BackupError::Invalid("duplicate_backup_vault"));
        }
    }
    if state.vaults.is_empty() {
        return Err(BackupError::Invalid("no_shared_vaults_found"));
    }
    state.spool.seek(SeekFrom::Start(0))?;
    Ok(Prepared {
        vaults: state.vaults,
        items: state.ids.len(),
        spool: state.spool,
    })
}

struct Root<'a>(&'a mut State);
struct Vaults<'a>(&'a mut State);
struct Vault<'a>(&'a mut State);
struct Items<'a>(&'a mut State);

macro_rules! seed {
    ($name:ident,$method:ident) => {
        impl<'de> DeserializeSeed<'de> for $name<'_> {
            type Value = ();
            fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
                d.$method(self)
            }
        }
    };
}
seed!(Root, deserialize_map);
seed!(Vaults, deserialize_seq);
seed!(Vault, deserialize_map);
seed!(Items, deserialize_seq);

impl<'de> Visitor<'de> for Root<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a shared v1 backup")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        loop {
            self.0.remaining.set(MAX_RECORD_BYTES);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate backup key"));
            }
            match key.as_str() {
                "version" => {
                    if map.next_value::<u32>()? != EXPORT_VERSION {
                        return Err(de::Error::custom("unsupported backup version"));
                    }
                }
                "scope" => {
                    if map.next_value::<String>()? != "shared" {
                        return Err(de::Error::custom("invalid backup scope"));
                    }
                }
                "plaintext" => {
                    if !map.next_value::<bool>()? {
                        return Err(de::Error::custom("plaintext backup required"));
                    }
                }
                "exported_at" => {
                    timestamp(&map.next_value::<String>()?).map_err(de::Error::custom)?;
                }
                "vaults" => map.next_value_seed(Vaults(self.0))?,
                _ => return Err(de::Error::custom("unknown backup field")),
            }
        }
        if seen.len() != 5 {
            return Err(de::Error::custom("missing backup field"));
        }
        Ok(())
    }
}
impl<'de> Visitor<'de> for Vaults<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("shared vaults")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            self.0.remaining.set(MAX_RECORD_BYTES);
            if self.0.vaults.len() >= MAX_VAULTS {
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("backup vault limit exceeded"));
                }
                break;
            }
            if seq.next_element_seed(Vault(self.0))?.is_none() {
                break;
            }
        }
        Ok(())
    }
}
impl<'de> Visitor<'de> for Vault<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a shared vault")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let (mut id, mut slug, mut name, mut count) = (None, None, None, None);
        let mut seen = HashSet::new();
        let start = self.0.ids.len();
        loop {
            self.0.remaining.set(MAX_RECORD_BYTES);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate backup key"));
            }
            match key.as_str() {
                "id" => id = Some(map.next_value()?),
                "slug" => slug = Some(map.next_value()?),
                "name" => name = Some(map.next_value()?),
                "item_count" => count = Some(map.next_value::<usize>()?),
                "items" => map.next_value_seed(Items(self.0))?,
                _ => return Err(de::Error::custom("unknown vault field")),
            }
        }
        if seen.len() != 5 || count != Some(self.0.ids.len() - start) {
            return Err(de::Error::custom("invalid vault fields or count"));
        }
        let vault = SharedExportVault {
            id: id.ok_or_else(|| de::Error::custom("missing vault id"))?,
            slug: slug.ok_or_else(|| de::Error::custom("missing vault slug"))?,
            name: name.ok_or_else(|| de::Error::custom("missing vault name"))?,
            item_count: count.ok_or_else(|| de::Error::custom("missing vault count"))?,
        };
        validate_vault(&vault).map_err(de::Error::custom)?;
        self.0.vaults.push(vault);
        Ok(())
    }
}
impl<'de> Visitor<'de> for Items<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("backup items")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            self.0.remaining.set(MAX_RECORD_BYTES);
            let Some(item) = seq.next_element::<SharedExportItem>()? else {
                break;
            };
            if self.0.ids.len() >= MAX_ITEMS {
                return Err(de::Error::custom("backup item limit exceeded"));
            }
            let id = validate_item(&item).map_err(de::Error::custom)?;
            let vault = self.0.vaults.len();
            if !self.0.ids.insert(id) || !self.0.paths.insert((vault, item.path.clone())) {
                return Err(de::Error::custom("duplicate backup item"));
            }
            if let Err(error) = self.0.stage(vault, item) {
                self.0.staging_error = Some(error);
                return Err(de::Error::custom("backup staging failed"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_io_failure_retains_the_original_error_source() {
        let mut source = tempfile::tempfile().expect("source");
        let value = serde_json::json!({"version":1,"scope":"shared","plaintext":true,"exported_at":"2026-11-14T00:00:00Z",
            "vaults":[{"id":"11111111-1111-4111-8111-111111111111","slug":"fixture","name":"Fixture","item_count":1,
              "items":[{"id":"22222222-2222-4222-8222-222222222222","path":"item","name":"item","type_id":"login","tags":null,"favorite":false,
                "payload":{"v":1,"typeId":"login","fields":{}},"checksum":"a".repeat(64),"version":1,"deleted_at":null,"updated_at":"2026-11-14T00:00:00Z"}]}]});
        source
            .write_all(value.to_string().as_bytes())
            .expect("write");
        source.rewind().expect("rewind");
        let target = tempfile::NamedTempFile::new().expect("target");
        let readonly = File::open(target.path()).expect("readonly target");
        let error = match prepare_into(source, readonly) {
            Err(error) => error,
            Ok(_) => panic!("write unexpectedly succeeded"),
        };
        let source = std::error::Error::source(&error).expect("original source");
        let source = source
            .downcast_ref::<std::io::Error>()
            .expect("I/O diagnostic preserved");
        assert_eq!(source.raw_os_error(), Some(libc::EBADF));
    }
}
