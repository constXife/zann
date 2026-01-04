use std::collections::HashMap;

use zann_core::EncryptedPayload;

use crate::cli_args::RenderArgs;
use crate::modules::shared::render_fs::{read_template_source, write_render_output};
use crate::modules::shared::TemplateToken;
use crate::modules::shared::{fetch_shared_item, resolve_path_for_context, resolve_shared_item_id};
use crate::modules::shared::{parse_template, parse_template_placeholder, secret_not_found_error};
use crate::modules::system::CommandContext;

pub(crate) async fn render_shared_template(
    args: RenderArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    let template = read_template_source(args.template.as_path())?;
    let tokens = parse_template(&template)?;
    let mut cache: HashMap<(String, String), EncryptedPayload> = HashMap::new();
    let mut out = String::new();

    for token in tokens {
        match token {
            TemplateToken::Text(text) => out.push_str(&text),
            TemplateToken::Placeholder(expr) => {
                let value =
                    resolve_template_placeholder(&expr, args.vault.as_deref(), ctx, &mut cache)
                        .await?;
                out.push_str(&value);
            }
        }
    }

    write_render_output(args.out.as_deref(), &out)?;
    Ok(())
}

#[cfg(test)]
fn render_template_tokens_sync<F>(
    tokens: &[TemplateToken],
    mut resolve: F,
) -> anyhow::Result<String>
where
    F: FnMut(&str) -> anyhow::Result<String>,
{
    let mut out = String::new();
    for token in tokens {
        match token {
            TemplateToken::Text(text) => out.push_str(text),
            TemplateToken::Placeholder(expr) => out.push_str(&resolve(expr)?),
        }
    }
    Ok(out)
}

async fn resolve_template_placeholder(
    expr: &str,
    vault: Option<&str>,
    ctx: &mut CommandContext<'_>,
    cache: &mut HashMap<(String, String), EncryptedPayload>,
) -> anyhow::Result<String> {
    let (selector, field) = parse_template_placeholder(expr)?;

    let (vault_id, path) = resolve_path_for_context(
        &selector,
        vault.map(|value| value.to_string()),
        ctx.context_name.as_deref(),
        ctx.config,
        ctx.client,
        ctx.addr,
        &ctx.access_token,
    )
    .await?;

    let payload = if let Some(payload) = cache.get(&(vault_id.clone(), path.clone())) {
        payload
    } else {
        let item_id = resolve_shared_item_id(
            ctx.client,
            ctx.addr,
            &ctx.access_token,
            &vault_id,
            None,
            Some(&path),
        )
        .await
        .map_err(|_| secret_not_found_error(&path))?;
        let item = fetch_shared_item(ctx.client, ctx.addr, &ctx.access_token, item_id).await?;
        cache.insert((vault_id.clone(), path.clone()), item.payload);
        cache
            .get(&(vault_id.clone(), path.clone()))
            .ok_or_else(|| anyhow::anyhow!("failed to cache payload for {}", path))?
    };

    let value = crate::find_field(payload, &field)
        .map(|item| item.value.clone())
        .ok_or_else(|| anyhow::anyhow!("field '{}' not found in {}", field, path))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{parse_template, render_template_tokens_sync};
    use crate::modules::shared::TemplateToken;
    use std::collections::HashMap;

    #[test]
    fn parse_template_simple() {
        let tokens = parse_template("hello {{ path#field }}!").expect("valid template");
        assert_eq!(tokens.len(), 3);
        assert!(matches!(
            tokens[0],
            TemplateToken::Text(ref text) if text == "hello "
        ));
        assert!(matches!(
            tokens[1],
            TemplateToken::Placeholder(ref expr) if expr == "path#field"
        ));
        assert!(matches!(
            tokens[2],
            TemplateToken::Text(ref text) if text == "!"
        ));
    }

    #[test]
    fn parse_template_rejects_unclosed_placeholder() {
        assert!(parse_template("hello {{ path").is_err());
    }

    #[test]
    fn parse_template_rejects_empty_placeholder() {
        assert!(parse_template("hello {{  }}").is_err());
    }

    #[test]
    fn render_template_tokens_substitutes() {
        let tokens = parse_template("a={{ one }} b={{ two#field }}").expect("valid template");
        let values = HashMap::from([
            ("one".to_string(), "1".to_string()),
            ("two#field".to_string(), "2".to_string()),
        ]);
        let out = render_template_tokens_sync(&tokens, |expr| {
            let value = values
                .get(expr)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing {expr}"));
            value
        })
        .expect("render output");
        assert_eq!(out, "a=1 b=2");
    }
}
