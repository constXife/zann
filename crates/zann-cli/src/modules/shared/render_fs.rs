use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;
use zann_client::delivery::PlannedDeliveryFile;
use zann_client::secrets::BatchResult;
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

pub(crate) fn validate_materialize_field(field: &str) -> anyhow::Result<()> {
    if field != "value" {
        anyhow::bail!("machine-secret materialization requires --field value");
    }
    Ok(())
}

pub(crate) async fn materialize_shared(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    prefix: Option<&str>,
    out: &Path,
    field: &str,
    skip_unchanged: bool,
    limit: usize,
) -> anyhow::Result<()> {
    validate_materialize_field(field)?;
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

pub(crate) fn publish_delivery_generation(
    out: &Path,
    plan: &[PlannedDeliveryFile],
    results: &[BatchResult],
    retain_generations: usize,
    skip_unchanged: bool,
) -> anyhow::Result<String> {
    if plan.len() != results.len() || !(1..=10).contains(&retain_generations) {
        anyhow::bail!("invalid delivery generation input");
    }
    prepare_materialize_root(out)?;
    let generations = out.join("generations");
    ensure_private_directory(&generations, true)?;
    if skip_unchanged {
        if let Some(id) = matching_current_generation(out, plan, results)? {
            return Ok(id);
        }
    }

    let generation = Uuid::now_v7().to_string();
    let generation_root = generations.join(&generation);
    create_private_generation_directory(&generation_root)?;
    ensure_private_directory(&generation_root, true)?;
    let mut cleanup = GenerationCleanup::new(generation_root.clone());

    for (planned, result) in plan.iter().zip(results) {
        if result.status != "ok" || result.path.trim_matches('/') != planned.secret() {
            anyhow::bail!("invalid delivery batch result");
        }
        let secret = result
            .secret
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("invalid delivery batch result"))?;
        let relative = normalize_output_path(planned.target())?;
        let target = generation_root.join(&relative);
        if let Some(parent) = relative.parent() {
            ensure_private_subdirectories(&generation_root, parent)?;
        }
        ensure_file_size(&secret.value)?;
        write_atomic_private(&target, secret.value.as_bytes())?;
    }
    sync_directory(&generation_root)?;
    sync_directory(&generations)?;

    write_atomic_private(&out.join("current"), format!("{generation}\n").as_bytes())?;
    cleanup.disarm();
    if let Err(error) = prune_generations(&generations, &generation, retain_generations) {
        tracing::warn!(error = %error, "unable to prune old delivery generations");
    }
    Ok(generation)
}

fn matching_current_generation(
    out: &Path,
    plan: &[PlannedDeliveryFile],
    results: &[BatchResult],
) -> anyhow::Result<Option<String>> {
    let current_path = out.join("current");
    let mut current = match open_existing_nofollow(&current_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_open_file(&current_path, &current)?;
    secure_file_permissions(&current)?;
    if current.metadata()?.len() > 64 {
        anyhow::bail!("invalid delivery generation pointer");
    }
    let mut pointer = String::new();
    current.read_to_string(&mut pointer)?;
    let id = pointer
        .strip_suffix('\n')
        .ok_or_else(|| anyhow::anyhow!("invalid delivery generation pointer"))?;
    if id.contains('\n') {
        anyhow::bail!("invalid delivery generation pointer");
    }
    let parsed =
        Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("invalid delivery generation pointer"))?;
    if parsed.get_version_num() != 7 {
        anyhow::bail!("invalid delivery generation pointer");
    }

    let generation_root = out.join("generations").join(id);
    ensure_private_directory(&generation_root, true)?;
    let expected = plan
        .iter()
        .map(|file| normalize_output_path(file.target()))
        .collect::<Result<HashSet<_>, _>>()?;
    let mut actual = HashSet::with_capacity(expected.len());
    collect_generation_files(&generation_root, &generation_root, &mut actual)?;
    if actual != expected {
        return Ok(None);
    }

    for (planned, result) in plan.iter().zip(results) {
        let secret = result
            .secret
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("invalid delivery batch result"))?;
        let target = generation_root.join(normalize_output_path(planned.target())?);
        if !is_same_contents(&target, &secret.value)? {
            return Ok(None);
        }
    }
    Ok(Some(id.to_string()))
}

fn collect_generation_files(
    root: &Path,
    directory: &Path,
    files: &mut HashSet<PathBuf>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("delivery generation contains a symlink");
        }
        if metadata.is_dir() {
            validate_private_directory_permissions(&path, &metadata)?;
            collect_generation_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow::anyhow!("invalid delivery generation path"))?;
            files.insert(relative.to_path_buf());
        } else {
            anyhow::bail!("delivery generation contains a non-file entry");
        }
    }
    Ok(())
}

fn create_private_generation_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    configure_private_directory(&mut builder);
    builder.create(path)
}

struct GenerationCleanup {
    path: PathBuf,
    armed: bool,
}

impl GenerationCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for GenerationCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn prune_generations(root: &Path, current: &str, retain: usize) -> anyhow::Result<()> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if Uuid::parse_str(&name).is_err() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("invalid delivery generation entry");
        }
        names.push(name);
    }
    names.sort_unstable_by(|left, right| right.cmp(left));
    let mut kept = 0usize;
    for name in names {
        if name == current || kept < retain.saturating_sub(1) {
            kept += usize::from(name != current);
            continue;
        }
        fs::remove_dir_all(root.join(name))?;
    }
    sync_directory(root)?;
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
#[path = "../../../tests/unit/render_fs.rs"]
mod tests;
