use std::fs;

use zann_client::delivery::{DeliveryPlan, MAX_DELIVERY_PROFILE_BYTES};

use crate::modules::delivery::args::{DeliveryArgs, DeliveryCommand};
use crate::modules::secrets::batch_get_with_refresh;
use crate::modules::shared::publish_delivery_generation;
use crate::modules::system::CommandContext;

pub(crate) async fn handle_delivery_command(
    args: DeliveryArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        DeliveryCommand::Apply(args) => {
            let source = read_profile(&args.profile)?;
            let plan = DeliveryPlan::from_yaml(&source)?;
            let paths = plan.secret_paths();
            let results = batch_get_with_refresh(ctx, plan.vault(), &paths).await?;
            if results.iter().any(|result| result.status == "error") {
                anyhow::bail!("one or more delivery profile secrets were unavailable");
            }
            let total_bytes = results.iter().try_fold(0usize, |total, result| {
                let value_bytes = result
                    .secret
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("invalid delivery batch result"))?
                    .value
                    .len();
                total
                    .checked_add(value_bytes)
                    .ok_or_else(|| anyhow::anyhow!("delivery profile values exceed sink capacity"))
            })?;
            if total_bytes > args.max_total_bytes {
                anyhow::bail!("delivery profile values exceed sink capacity");
            }
            let generation = publish_delivery_generation(
                &args.out,
                plan.files(),
                &results,
                args.retain_generations,
                args.skip_unchanged,
            )?;
            println!("{generation}");
            Ok(())
        }
    }
}

fn read_profile(path: &std::path::Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        anyhow::bail!("delivery profile is not a regular file");
    }
    if metadata.len() > MAX_DELIVERY_PROFILE_BYTES as u64 {
        anyhow::bail!("delivery profile exceeds {MAX_DELIVERY_PROFILE_BYTES} bytes");
    }
    let source = fs::read_to_string(path)?;
    if source.len() > MAX_DELIVERY_PROFILE_BYTES {
        anyhow::bail!("delivery profile exceeds {MAX_DELIVERY_PROFILE_BYTES} bytes");
    }
    Ok(source)
}
