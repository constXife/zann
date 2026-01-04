#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::ref_option)]
#![allow(clippy::single_match_else)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_wraps)]

pub mod app;
pub mod bootstrap;
pub mod config;
pub mod domains;
pub mod http;
pub mod infra;
pub mod runtime;
pub mod settings;

pub mod oidc {
    pub use crate::domains::auth::core::oidc::*;
}

pub mod passwords {
    pub use crate::domains::auth::core::passwords::*;
}

pub mod tokens {
    pub use crate::domains::auth::core::tokens::*;
}
