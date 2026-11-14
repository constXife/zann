//! Version-one IPC. Signatures cover exact UTF-8 JSON bytes, never a
//! reserialized object. A one-time code authenticates the first server pin.
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

mod error;
pub use error::{IpcError, Result};
mod model;
pub use model::*;

pub const VERSION: u8 = 1;
pub const MAX_BODY_BYTES: usize = 128 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u8,
    pub server_key: String,
    pub nonce: String,
    pub transport_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub public_key: String,
    pub sequence: u64,
    pub body: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReply {
    pub sequence: u64,
    pub body: String,
    pub signature: String,
}

impl Drop for SignedRequest {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Drop for SignedReply {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    PairStatus {},
    PairStart {
        name: String,
        message: String,
    },
    PairFinish {
        confirmation: String,
    },
    Query {
        context: BrowserContext,
        cursor: Option<String>,
    },
    Save {
        context: BrowserContext,
        scope: BrowserScope,
        login: CapturedLogin,
        gesture: bool,
    },
    Fill {
        context: BrowserContext,
        item_id: String,
        gesture: bool,
        include_totp: bool,
    },
}

/// All errors on the browser wire are closed codes without source/error text.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Timeout,
    Unpaired,
    Locked,
    Refused,
    Limit,
    Internal,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    PairChallenge {
        message: String,
        confirmation: String,
    },
    Paired {},
    Matches {
        page: MatchPage,
    },
    Filled {
        value: String,
        totp: Option<String>,
    },
    Saved {
        item_id: String,
    },
    Error {
        code: ErrorCode,
    },
}

impl Drop for Reply {
    fn drop(&mut self) {
        if let Self::Filled { value, totp } = self {
            value.zeroize();
            totp.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchPage {
    pub items: Vec<BrowserMatch>,
    pub scope: BrowserScope,
    pub next_cursor: Option<String>,
}

mod auth;
pub use auth::decode_array;

mod encrypted;
pub use encrypted::{EncryptedFrame, NoiseHandshakePacket};

mod client;
pub use client::BrowserClient;

mod pairing;
pub use pairing::{pairing_binding, BrowserPairingClient};

mod search;
pub use search::{LoginSearch, LoginSearchResult, SearchError, SEARCH_MAX_MATCHES};

mod usage;
pub use usage::{BrowserUsage, MAX_USAGE_BYTES, MAX_USAGE_ENTRIES};
