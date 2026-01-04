use crate::modules::shared::VaultListResponse;

pub(crate) async fn fetch_vaults(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> anyhow::Result<VaultListResponse> {
    let url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Vault list failed: {status} {body}");
    }
    Ok(response.json::<VaultListResponse>().await?)
}
