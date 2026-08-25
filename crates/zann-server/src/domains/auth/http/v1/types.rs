use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
pub(crate) struct PreloginQuery {
    pub(crate) email: String,
}
