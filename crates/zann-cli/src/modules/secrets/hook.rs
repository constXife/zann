use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use zann_client::secrets::{
    RotationCandidateResponse, RotationCommitResponse, RotationStatusResponse, SecretsClientError,
};
use zeroize::Zeroizing;

use super::actions::{secrets_client, should_refresh};
use super::args::RotationHookArgs;
use super::get_with_refresh;
use crate::modules::shared::resolve_vault_arg;
use crate::modules::system::http::refresh_service_account_access_token;
use crate::modules::system::CommandContext;

const COMMIT_SAFETY_MARGIN: Duration = Duration::from_secs(15);

#[derive(Serialize)]
struct HookInput<'a> {
    previous: &'a str,
    candidate: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookFailure {
    Spawn,
    Stdin,
    Exit,
    Timeout,
    Interrupted,
    VersionChanged,
}

impl HookFailure {
    const fn abort_reason(self) -> &'static str {
        match self {
            Self::Spawn => "rotation hook could not be started",
            Self::Stdin => "rotation hook did not accept its input",
            Self::Exit => "rotation hook exited unsuccessfully",
            Self::Timeout => "rotation hook timed out",
            Self::Interrupted => "rotation hook was interrupted",
            Self::VersionChanged => "secret version changed before rotation start",
        }
    }
}

pub(crate) async fn handle_rotation_hook(
    args: RotationHookArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    let vault = resolve_vault_arg(args.vault.clone(), ctx).await?;
    let previous = get_with_refresh(ctx, &vault, &args.path, false).await?;
    let item_id = Uuid::parse_str(&previous.item_id)
        .map_err(|_| anyhow::anyhow!("server returned an invalid secret item id"))?;
    let started = rotation_start_with_refresh(ctx, item_id, args.policy.as_deref())
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "rotation start failed or its outcome is ambiguous; inspect rotate/status before retrying: {error}"
            )
        })?;
    if started.previous_version != previous.version {
        abort_after_hook_failure(ctx, item_id, HookFailure::VersionChanged).await?;
        anyhow::bail!(HookFailure::VersionChanged.abort_reason());
    }
    let timeout = match hook_timeout(&started, args.timeout_seconds) {
        Ok(timeout) => timeout,
        Err(error) => {
            abort_after_hook_failure(ctx, item_id, HookFailure::Timeout).await?;
            return Err(error);
        }
    };

    if let Err(failure) = run_hook(
        &args,
        previous.value.as_str(),
        started.candidate.as_str(),
        timeout,
    )
    .await
    {
        abort_after_hook_failure(ctx, item_id, failure).await?;
        anyhow::bail!(failure.abort_reason());
    }

    let committed = rotation_commit_with_refresh(ctx, item_id)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "rotation hook succeeded, but commit failed; rotation remains recoverable: {error}"
            )
        })?;
    println!("committed version {}", committed.version);
    Ok(())
}

fn hook_timeout(
    started: &RotationCandidateResponse,
    requested_seconds: u64,
) -> anyhow::Result<Duration> {
    let expires_at = started
        .expires_at
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("rotation start response omitted expires_at"))?;
    let expires_at = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| anyhow::anyhow!("rotation start response contained invalid expires_at"))?
        .with_timezone(&Utc);
    let remaining = (expires_at - Utc::now())
        .to_std()
        .map_err(|_| anyhow::anyhow!("rotation expired before the hook started"))?;
    let available = remaining
        .checked_sub(COMMIT_SAFETY_MARGIN)
        .ok_or_else(|| anyhow::anyhow!("rotation expires too soon to run the hook"))?;
    let requested = Duration::from_secs(requested_seconds);
    let timeout = requested.min(available);
    if timeout.is_zero() {
        anyhow::bail!("rotation expires too soon to run the hook");
    }
    Ok(timeout)
}

async fn run_hook(
    args: &RotationHookArgs,
    previous: &str,
    candidate: &str,
    timeout: Duration,
) -> Result<(), HookFailure> {
    let input = Zeroizing::new(
        serde_json::to_vec(&HookInput {
            previous,
            candidate,
        })
        .map_err(|_| HookFailure::Stdin)?,
    );
    let mut command = tokio::process::Command::new(&args.exec);
    command
        .args(&args.exec_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    for name in [
        "ZANN_SERVICE_TOKEN",
        "ZANN_ACCESS_TOKEN",
        "ZANN_TOKEN",
        "ZANN_TOKEN_FILE",
    ] {
        command.env_remove(name);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    let mut child = command.spawn().map_err(|_| HookFailure::Spawn)?;
    let process_id = child.id();
    let mut stdin = child.stdin.take().ok_or(HookFailure::Stdin)?;
    if stdin.write_all(&input).await.is_err() || stdin.shutdown().await.is_err() {
        terminate_hook(&mut child, process_id).await;
        return Err(HookFailure::Stdin);
    }
    drop(stdin);

    let outcome = tokio::select! {
        status = child.wait() => match status {
            Ok(status) if status.success() => Ok(()),
            Ok(_) => Err(HookFailure::Exit),
            Err(_) => Err(HookFailure::Exit),
        },
        _ = tokio::time::sleep(timeout) => Err(HookFailure::Timeout),
        signal = tokio::signal::ctrl_c() => {
            let _ = signal;
            Err(HookFailure::Interrupted)
        },
    };
    if matches!(
        outcome,
        Err(HookFailure::Timeout | HookFailure::Interrupted)
    ) {
        terminate_hook(&mut child, process_id).await;
    }
    outcome
}

async fn terminate_hook(child: &mut tokio::process::Child, process_id: Option<u32>) {
    #[cfg(unix)]
    if let Some(process_id) = process_id.and_then(|value| i32::try_from(value).ok()) {
        // The hook is placed in its own process group, so descendants cannot
        // keep applying a candidate after Zann aborts the rotation.
        unsafe {
            libc::kill(-process_id, libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn abort_after_hook_failure(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
    failure: HookFailure,
) -> anyhow::Result<()> {
    rotation_abort_with_refresh(ctx, item_id, failure.abort_reason())
        .await
        .map(|_| ())
        .map_err(|error| {
            anyhow::anyhow!(
                "{}; abort also failed and rotation remains active: {error}",
                failure.abort_reason()
            )
        })
}

async fn rotation_start_with_refresh(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
    policy: Option<&str>,
) -> anyhow::Result<RotationCandidateResponse> {
    match secrets_client(ctx)?.rotation_start(item_id, policy).await {
        Err(error) if should_refresh(&error) => {
            refresh_or_return(ctx, error).await?;
            Ok(secrets_client(ctx)?.rotation_start(item_id, policy).await?)
        }
        result => Ok(result?),
    }
}

async fn rotation_commit_with_refresh(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
) -> anyhow::Result<RotationCommitResponse> {
    match secrets_client(ctx)?.rotation_commit(item_id).await {
        Err(error) if should_refresh(&error) => {
            refresh_or_return(ctx, error).await?;
            Ok(secrets_client(ctx)?.rotation_commit(item_id).await?)
        }
        result => Ok(result?),
    }
}

async fn rotation_abort_with_refresh(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
    reason: &str,
) -> anyhow::Result<RotationStatusResponse> {
    match secrets_client(ctx)?
        .rotation_abort(item_id, Some(reason), false)
        .await
    {
        Err(error) if should_refresh(&error) => {
            refresh_or_return(ctx, error).await?;
            Ok(secrets_client(ctx)?
                .rotation_abort(item_id, Some(reason), false)
                .await?)
        }
        result => Ok(result?),
    }
}

async fn refresh_or_return(
    ctx: &mut CommandContext<'_>,
    error: SecretsClientError,
) -> anyhow::Result<()> {
    if refresh_service_account_access_token(ctx).await? {
        Ok(())
    } else {
        Err(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zann_core::api::secrets::RotationCandidate;

    fn started(expires_at: DateTime<Utc>) -> RotationCandidateResponse {
        RotationCandidateResponse {
            state: "rotating".to_string(),
            candidate: RotationCandidate::new("candidate".to_string()),
            previous_version: 1,
            expires_at: Some(expires_at.to_rfc3339()),
            recover_until: None,
        }
    }

    #[test]
    fn hook_timeout_is_capped_before_server_expiry() {
        let timeout = hook_timeout(&started(Utc::now() + chrono::Duration::seconds(30)), 300)
            .expect("timeout");
        assert!(timeout <= Duration::from_secs(15));
        assert!(timeout > Duration::from_secs(13));
    }

    #[test]
    fn hook_timeout_rejects_expired_rotation() {
        assert!(hook_timeout(&started(Utc::now() - chrono::Duration::seconds(1)), 300).is_err());
    }
}
