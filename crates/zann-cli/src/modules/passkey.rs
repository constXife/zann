//! Shell arguments and reporting only; codecs/file custody belong to the client.
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use zann_client::passkey_exchange::{self, CxfExportContext, ExchangeFormat};
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Cxf,
    Bitwarden,
    KeepassXcPasskey,
    KeepassXml,
}
#[derive(Parser)]
pub(crate) struct Args {
    #[arg(long, value_enum)]
    format: Format,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Acknowledge that both input and output contain plaintext private keys.
    #[arg(long, required = true)]
    accept_plaintext: bool,
    /// Public exporter account identity for the CXF header; never a secret.
    #[arg(long)]
    account_id: uuid::Uuid,
    #[arg(long)]
    username: String,
    #[arg(long)]
    email: String,
}
pub(crate) fn convert(args: &Args) -> anyhow::Result<()> {
    let format = match args.format {
        Format::Cxf => ExchangeFormat::Cxf,
        Format::Bitwarden => ExchangeFormat::Bitwarden,
        Format::KeepassXcPasskey => ExchangeFormat::KeepassXcPasskey,
        Format::KeepassXml => ExchangeFormat::KeepassXml,
    };
    let count = passkey_exchange::convert_to_cxf(
        &args.input,
        format,
        &args.output,
        CxfExportContext {
            timestamp: chrono::Utc::now(),
            account_id: args.account_id.as_bytes(),
            username: &args.username,
            email: &args.email,
        },
    )?;
    println!("Converted {count} passkeys. The output contains plaintext private keys.");
    Ok(())
}
