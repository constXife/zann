use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct DeliveryArgs {
    #[command(subcommand)]
    pub command: DeliveryCommand,
}

#[derive(Subcommand)]
pub enum DeliveryCommand {
    #[command(about = "Resolve and atomically publish a delivery profile")]
    Apply(DeliveryApplyArgs),
}

#[derive(Args)]
pub struct DeliveryApplyArgs {
    #[arg(long, help = "Value-free YAML delivery profile")]
    pub profile: PathBuf,
    #[arg(long, help = "Private generation store")]
    pub out: PathBuf,
    #[arg(
        long,
        default_value_t = 2,
        value_parser = parse_retention,
        help = "Number of complete generations to retain (1-10)"
    )]
    pub retain_generations: usize,
    #[arg(
        long,
        default_value_t = 16 * 1024 * 1024,
        value_parser = parse_total_bytes,
        help = "Maximum aggregate secret bytes accepted by the sink"
    )]
    pub max_total_bytes: usize,
    #[arg(
        long,
        help = "Reuse the current generation when targets and values are identical"
    )]
    pub skip_unchanged: bool,
}

fn parse_retention(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "retention must be an integer from 1 to 10".to_string())?;
    if !(1..=10).contains(&parsed) {
        return Err("retention must be an integer from 1 to 10".to_string());
    }
    Ok(parsed)
}

fn parse_total_bytes(value: &str) -> Result<usize, String> {
    const MAX: usize = 16 * 1024 * 1024;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("maximum total bytes must be an integer from 1 to {MAX}"))?;
    if !(1..=MAX).contains(&parsed) {
        return Err(format!(
            "maximum total bytes must be an integer from 1 to {MAX}"
        ));
    }
    Ok(parsed)
}
