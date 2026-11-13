//! What a client shows about the open storage's sync: one indicator, its
//! label and what pressing it does, so every shell renders the same state.
//!
//! The shell supplies what it knows (whether a server syncs the storage, how
//! many changes wait, whether a sync runs or the last one failed); this module
//! decides which of those the user sees first.

/// Whether a server syncs the storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncLink {
    /// A server connection syncs it.
    Connected,
    /// A server's storage no connection syncs any more.
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncStatusInput<'a> {
    pub link: SyncLink,
    pub server_url: Option<&'a str>,
    pub pending_changes: u64,
    /// A sync of this storage is running.
    pub syncing: bool,
    /// The last sync of this storage failed.
    pub failed: bool,
}

/// The indicator's state, most urgent first: a storage nothing syncs, a sync
/// in progress, a failed one, changes waiting, everything sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncIndicator {
    Disconnected {
        server: String,
        pending_changes: u64,
    },
    Syncing {
        server: String,
    },
    Failed {
        server: String,
        pending_changes: u64,
    },
    Pending {
        server: String,
        pending_changes: u64,
    },
    Synced {
        server: String,
    },
}

/// What pressing the indicator does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncAction {
    None,
    SyncNow,
    /// Lead to connecting the storage's server again.
    Reconnect,
}

#[must_use]
pub fn sync_indicator(input: SyncStatusInput<'_>) -> SyncIndicator {
    let server = || input.server_url.map(server_label).unwrap_or_default();
    let pending_changes = input.pending_changes;
    match input.link {
        SyncLink::Disconnected => SyncIndicator::Disconnected {
            server: server(),
            pending_changes,
        },
        SyncLink::Connected if input.syncing => SyncIndicator::Syncing { server: server() },
        SyncLink::Connected if input.failed => SyncIndicator::Failed {
            server: server(),
            pending_changes,
        },
        SyncLink::Connected if pending_changes > 0 => SyncIndicator::Pending {
            server: server(),
            pending_changes,
        },
        SyncLink::Connected => SyncIndicator::Synced { server: server() },
    }
}

impl SyncIndicator {
    /// The catalogue key of the indicator's label; [`Self::label_args`] fills it.
    #[must_use]
    pub fn label_key(&self) -> &'static str {
        match self {
            Self::Disconnected { .. } => "sync.disconnected",
            Self::Syncing { .. } => "sync.syncing",
            Self::Failed { .. } => "sync.failed",
            Self::Pending { .. } => "sync.pending",
            Self::Synced { .. } => "sync.synced",
        }
    }

    #[must_use]
    pub fn label_args(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Syncing { server } | Self::Synced { server } => {
                vec![("server", server.clone())]
            }
            Self::Disconnected {
                server,
                pending_changes,
            }
            | Self::Failed {
                server,
                pending_changes,
            }
            | Self::Pending {
                server,
                pending_changes,
            } => vec![
                ("server", server.clone()),
                ("count", pending_changes.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn action(&self) -> SyncAction {
        match self {
            Self::Syncing { .. } => SyncAction::None,
            Self::Disconnected { .. } => SyncAction::Reconnect,
            Self::Failed { .. } | Self::Pending { .. } | Self::Synced { .. } => SyncAction::SyncNow,
        }
    }

    /// Whether the indicator asks for attention rather than reporting.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::Disconnected { .. } | Self::Failed { .. })
    }
}

/// The host a server address names, as the indicator shows it.
fn server_label(url: &str) -> String {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// A storage context names its server when remote, and its stored name when local.
pub fn storage_context_label(name: &str, server_url: Option<&str>) -> String {
    match server_url {
        Some(url) => server_label(url),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(link: SyncLink) -> SyncStatusInput<'static> {
        SyncStatusInput {
            link,
            server_url: Some("https://zann.example.test/"),
            pending_changes: 0,
            syncing: false,
            failed: false,
        }
    }

    #[test]
    fn the_most_urgent_state_shows_first() {
        let busy = SyncStatusInput {
            pending_changes: 3,
            syncing: true,
            failed: true,
            ..input(SyncLink::Disconnected)
        };
        assert!(matches!(
            sync_indicator(busy),
            SyncIndicator::Disconnected {
                pending_changes: 3,
                ..
            }
        ));
        let connected = SyncStatusInput {
            link: SyncLink::Connected,
            ..busy
        };
        assert!(matches!(
            sync_indicator(connected),
            SyncIndicator::Syncing { .. }
        ));
        let idle = SyncStatusInput {
            syncing: false,
            ..connected
        };
        assert!(matches!(sync_indicator(idle), SyncIndicator::Failed { .. }));
        let ok = SyncStatusInput {
            failed: false,
            ..idle
        };
        assert!(matches!(
            sync_indicator(ok),
            SyncIndicator::Pending {
                pending_changes: 3,
                ..
            }
        ));
        let sent = SyncStatusInput {
            pending_changes: 0,
            ..ok
        };
        assert_eq!(
            sync_indicator(sent),
            SyncIndicator::Synced {
                server: "zann.example.test".to_string()
            }
        );
    }

    #[test]
    fn each_state_has_a_label_and_an_action() {
        let gone = sync_indicator(SyncStatusInput {
            pending_changes: 2,
            ..input(SyncLink::Disconnected)
        });
        assert_eq!(gone.label_key(), "sync.disconnected");
        assert_eq!(
            gone.label_args(),
            vec![
                ("server", "zann.example.test".to_string()),
                ("count", "2".to_string())
            ]
        );
        assert_eq!(gone.action(), SyncAction::Reconnect);
        assert!(gone.needs_attention());

        let synced = sync_indicator(input(SyncLink::Connected));
        assert_eq!(synced.action(), SyncAction::SyncNow);
        assert!(!synced.needs_attention());
    }

    #[test]
    fn the_server_shows_as_its_host() {
        assert_eq!(
            server_label("https://zann.example.test:8443/api?x#y"),
            "zann.example.test:8443"
        );
        assert_eq!(server_label("zann.example.test"), "zann.example.test");
    }
}
