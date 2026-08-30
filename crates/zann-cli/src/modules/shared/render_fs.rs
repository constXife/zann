use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use zann_client::secrets::MAX_BATCH_SECRETS;

use crate::modules::secrets::{batch_get_with_refresh, list_with_refresh};
use crate::modules::system::CommandContext;

const MAX_MATERIALIZED_FILE_BYTES: usize = 256 * 1_024;
const MAX_MATERIALIZED_PATH_BYTES: usize = 500;
const MAX_MATERIALIZED_PATH_SEGMENTS: usize = 32;
const MAX_MATERIALIZED_SEGMENT_BYTES: usize = 200;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

pub(crate) async fn materialize_shared(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    prefix: Option<&str>,
    out: &Path,
    field: &str,
    skip_unchanged: bool,
    limit: usize,
) -> anyhow::Result<()> {
    if field != "value" {
        anyhow::bail!("machine-secret materialization requires --field value");
    }
    prepare_materialize_root(out)?;
    let mut cursor: Option<String> = None;
    loop {
        let response = list_with_refresh(ctx, vault_id, prefix, limit, cursor.as_deref()).await?;

        let paths = response
            .secrets
            .into_iter()
            .map(|secret| secret.path)
            .collect::<Vec<_>>();
        for chunk in paths.chunks(MAX_BATCH_SECRETS) {
            let results = batch_get_with_refresh(ctx, vault_id, chunk).await?;
            if results.iter().any(|result| result.status == "error") {
                anyhow::bail!(
                    "one or more machine secrets were unavailable during materialization"
                );
            }

            for result in &results {
                let secret = result
                    .secret
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("invalid machine-secret batch response"))?;
                let rel = normalize_output_path(&secret.path)?;
                let target = out.join(&rel);
                if let Some(relative_parent) = rel.parent() {
                    ensure_private_subdirectories(out, relative_parent)?;
                }
                ensure_file_size(&secret.value)?;
                if skip_unchanged && is_same_contents(&target, &secret.value)? {
                    continue;
                }
                write_atomic_private(&target, secret.value.as_bytes())?;
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
                    ensure_private_directory(parent, false)?;
                }
            }
            ensure_file_size(contents)?;
            write_atomic_private(path, contents.as_bytes())?;
        }
    }
    Ok(())
}

fn is_same_contents(path: &Path, contents: &str) -> anyhow::Result<bool> {
    let mut existing = match open_existing_nofollow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    validate_open_file(path, &existing)?;
    secure_file_permissions(&existing)?;
    let metadata = existing.metadata()?;
    if metadata.len() != contents.len() as u64
        || metadata.len() > MAX_MATERIALIZED_FILE_BYTES as u64
    {
        return Ok(false);
    }
    let mut bytes = Vec::with_capacity(contents.len());
    existing.read_to_end(&mut bytes)?;
    Ok(bytes == contents.as_bytes())
}

fn write_atomic_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if contents.len() > MAX_MATERIALIZED_FILE_BYTES {
        anyhow::bail!(
            "materialized file exceeds {} bytes: {}",
            MAX_MATERIALIZED_FILE_BYTES,
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid output path"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    validate_target_if_exists(path)?;

    let (tmp_path, mut temporary) = create_private_temporary(parent)?;
    let mut cleanup = TemporaryCleanup::new(tmp_path.clone());
    temporary.write_all(contents)?;
    temporary.flush()?;
    temporary.sync_all()?;
    drop(temporary);

    atomic_replace(&tmp_path, path)?;
    cleanup.disarm();
    sync_directory(parent)?;
    Ok(())
}

fn ensure_file_size(contents: &str) -> anyhow::Result<()> {
    if contents.len() > MAX_MATERIALIZED_FILE_BYTES {
        anyhow::bail!(
            "materialized value exceeds {} bytes",
            MAX_MATERIALIZED_FILE_BYTES
        );
    }
    Ok(())
}

fn prepare_materialize_root(out: &Path) -> anyhow::Result<()> {
    ensure_private_directory(out, true)
}

fn ensure_private_directory(path: &Path, harden_existing: bool) -> anyhow::Result<()> {
    let existed = path.exists();
    if !existed {
        create_private_directories(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "output directory is not a real directory: {}",
            path.display()
        );
    }
    if harden_existing {
        validate_private_directory_permissions(path, &metadata)?;
    }
    Ok(())
}

fn ensure_private_subdirectories(root: &Path, relative: &Path) -> anyhow::Result<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("invalid output directory: {}", relative.display());
        };
        current.push(name);
        ensure_private_directory(&current, true)?;
    }
    Ok(())
}

fn create_private_directories(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    configure_private_directory(&mut builder);
    builder.create(path)
}

fn create_private_temporary(parent: &Path) -> anyhow::Result<(PathBuf, File)> {
    for _ in 0..32 {
        let path = parent.join(format!(".zann.tmp.{:016x}", rand::random::<u64>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_private_file(&mut options);
        match options.open(&path) {
            Ok(file) => {
                validate_open_file(&path, &file)?;
                secure_file_permissions(&file)?;
                return Ok((path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    anyhow::bail!("unable to allocate a temporary output file")
}

fn open_existing_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_nofollow(&mut options);
    options.open(path)
}

fn validate_target_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("refusing to replace symlink: {}", path.display());
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!("output target is not a regular file: {}", path.display());
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn validate_open_file(path: &Path, file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!("output target is not a regular file: {}", path.display());
    }
    validate_single_link(path, &metadata)
}

struct TemporaryCleanup {
    path: Option<PathBuf>,
}

impl TemporaryCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn configure_private_directory(builder: &mut fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt;

    builder.mode(PRIVATE_DIRECTORY_MODE);
}

#[cfg(not(unix))]
fn configure_private_directory(_builder: &mut fs::DirBuilder) {}

#[cfg(unix)]
fn configure_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(PRIVATE_FILE_MODE);
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_private_file(options: &mut OpenOptions) {
    configure_nofollow(options);
}

#[cfg(not(any(unix, windows)))]
fn configure_private_file(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_nofollow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_nofollow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_nofollow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn validate_private_directory_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE {
        anyhow::bail!("output directory must have mode 0700: {}", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_file_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
}

#[cfg(not(unix))]
fn secure_file_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_single_link(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        anyhow::bail!("refusing multiply-linked output file: {}", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_single_link(_path: &Path, _metadata: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) fn normalize_output_path(path: &str) -> anyhow::Result<PathBuf> {
    let trimmed = path.trim();
    let trimmed = trimmed.trim_matches('/');
    let segments = trimmed.split('/').collect::<Vec<_>>();
    if trimmed.is_empty()
        || trimmed.len() > MAX_MATERIALIZED_PATH_BYTES
        || segments.len() > MAX_MATERIALIZED_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_MATERIALIZED_SEGMENT_BYTES
                || segment.starts_with('.')
                || segment.trim() != *segment
                || segment.chars().any(char::is_control)
        })
    {
        anyhow::bail!("invalid materialization output path");
    }
    let rel = Path::new(trimmed);
    for component in rel.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow::anyhow!("invalid materialization output path"));
            }
        }
    }
    Ok(rel.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_file_size, ensure_private_directory, materialize_shared, normalize_output_path,
        write_atomic_private,
    };
    use crate::modules::system::{CliConfig, CommandContext};
    use mockito::{Matcher, Server};
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
        assert!(normalize_output_path("foo/.hidden").is_err());
        assert!(normalize_output_path("foo/line\nbreak").is_err());
        assert!(normalize_output_path("/").is_err());
        let path = normalize_output_path("/etc").expect("leading slash normalized");
        assert_eq!(path, PathBuf::from("etc"));
    }

    #[test]
    fn materialized_values_are_bounded() {
        assert!(ensure_file_size(&"x".repeat(super::MAX_MATERIALIZED_FILE_BYTES)).is_ok());
        assert!(ensure_file_size(&"x".repeat(super::MAX_MATERIALIZED_FILE_BYTES + 1)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_replaces_inode_with_private_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("secret");
        std::fs::write(&target, "old").expect("old secret");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        let old_inode = std::fs::metadata(&target).expect("metadata").ino();

        write_atomic_private(&target, b"new").expect("atomic write");

        let metadata = std::fs::metadata(&target).expect("metadata");
        assert_ne!(metadata.ino(), old_inode);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&target).expect("secret"), "new");
        assert!(std::fs::read_dir(directory.path())
            .expect("directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".zann.tmp.")));
    }

    #[cfg(unix)]
    #[test]
    fn writer_and_directory_setup_reject_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempdir().expect("tempdir");
        let real_file = directory.path().join("real-secret");
        let linked_file = directory.path().join("linked-secret");
        std::fs::write(&real_file, "old").expect("real secret");
        symlink(&real_file, &linked_file).expect("file symlink");

        assert!(write_atomic_private(&linked_file, b"new").is_err());
        assert_eq!(
            std::fs::read_to_string(&real_file).expect("real secret"),
            "old"
        );

        let real_directory = directory.path().join("real-directory");
        let linked_directory = directory.path().join("linked-directory");
        std::fs::create_dir(&real_directory).expect("real directory");
        symlink(&real_directory, &linked_directory).expect("directory symlink");
        assert!(ensure_private_directory(&linked_directory, true).is_err());

        let permissive_directory = directory.path().join("permissive-directory");
        std::fs::create_dir(&permissive_directory).expect("permissive directory");
        std::fs::set_permissions(
            &permissive_directory,
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("permissive mode");
        assert!(ensure_private_directory(&permissive_directory, true).is_err());
        assert_eq!(
            std::fs::metadata(&permissive_directory)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[tokio::test]
    async fn materialize_writes_files() {
        let mut server = Server::new_async().await;
        let vault_id = "vault-1";
        let list_body = json!({
            "secrets": [{
                "path": "/alpha/one",
                "version": 1,
                "updated_at": "2024-01-01T00:00:00Z"
            }]
        });

        let list_mock = server
            .mock("GET", "/v1/vaults/vault-1/secrets")
            .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
            .with_status(200)
            .with_body(list_body.to_string())
            .create_async()
            .await;

        let batch_body = json!([{
            "path": "alpha/one",
            "status": "ok",
            "secret": {
                "item_id": "00000000-0000-0000-0000-000000000001",
                "path": "/alpha/one",
                "vault_id": "vault-1",
                "value": "secret",
                "policy": "default",
                "version": 1
            }
        }]);
        let batch_mock = server
            .mock("POST", "/v1/vaults/vault-1/secrets/batch/get")
            .match_body(Matcher::Json(json!({"paths": ["alpha/one"]})))
            .with_status(200)
            .with_body(batch_body.to_string())
            .create_async()
            .await;

        let out_dir = tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private output directory");
        }
        let client = reqwest::Client::new();
        let server_url = server.url();
        let mut config = CliConfig::default();
        let mut ctx = CommandContext {
            client: &client,
            addr: &server_url,
            allow_insecure: true,
            access_token: "token".to_string(),
            context_name: None,
            token_name: None,
            config: &mut config,
        };
        materialize_shared(
            &mut ctx,
            vault_id,
            None,
            out_dir.path(),
            "value",
            false,
            100,
        )
        .await
        .expect("materialize ok");

        let target = out_dir.path().join("alpha/one");
        let contents = std::fs::read_to_string(target).expect("secret");
        assert_eq!(contents, "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let directory_mode = std::fs::metadata(out_dir.path().join("alpha"))
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(out_dir.path().join("alpha/one"))
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
        list_mock.assert_async().await;
        batch_mock.assert_async().await;
    }
}
