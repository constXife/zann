use super::*;

fn entry(version: i64, pending: bool) -> ItemHistorySummary {
    ItemHistorySummary {
        version,
        checksum: format!("checksum-{version}"),
        change_type: 1,
        changed_by_name: None,
        changed_by_email: String::new(),
        created_at: "2026-08-26T12:30:00.948547+00:00".into(),
        pending,
    }
}

fn state_with_preview() -> State {
    let detail = Detail::parse(ItemDetail {
        id: "item".into(),
        title: "Example".into(),
        path: "Example".into(),
        type_id: "login".into(),
        payload_json: r#"{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"synthetic"}}}"#.into(),
    }).unwrap();
    let mut state = State::new(&detail);
    assert!(matches!(
        state.update(Message::EntriesLoaded(Ok(vec![
            entry(2, true),
            entry(1, false)
        ]))),
        Outcome::LoadVersion { version: 2, .. }
    ));
    state.version_loading = false;
    state.detail = Some(detail);
    state
}

#[test]
fn metadata_refresh_preserves_selected_version_preview_and_masking() {
    let mut state = state_with_preview();
    for revealed in [false, true] {
        state.detail.as_mut().unwrap().fields[0].revealed = revealed;
        assert!(matches!(
            state.update(Message::EntriesRefreshed(Ok(vec![
                entry(3, false),
                entry(2, false),
                entry(1, false)
            ]))),
            Outcome::None
        ));
        assert_eq!(state.selected_version, Some(2));
        assert!(!state.entries[1].pending);
        assert_eq!(state.detail.as_ref().unwrap().fields[0].revealed, revealed);
        assert!(!state.version_loading);
    }
}

#[test]
fn changed_or_removed_version_discards_its_preview_before_reloading() {
    for removed in [false, true] {
        let mut state = state_with_preview();
        let mut entries = vec![entry(1, false)];
        if !removed {
            let mut changed = entry(2, false);
            changed.checksum = "different-payload".into();
            entries.insert(0, changed);
        }
        let expected = if removed { 1 } else { 2 };
        assert!(matches!(
            state.update(Message::EntriesRefreshed(Ok(entries))),
            Outcome::LoadVersion { version, .. } if version == expected
        ));
        assert!(state.detail.is_none());
        assert!(state.version_loading);
    }
}

#[test]
fn failed_metadata_refresh_keeps_the_preview_and_reports_the_error() {
    let mut state = state_with_preview();
    state.update(Message::EntriesRefreshed(Err("history read failed".into())));
    assert_eq!(state.selected_version, Some(2));
    assert!(state.detail.is_some());
    assert_eq!(state.error.as_deref(), Some("history read failed"));
}

#[test]
fn a_superseded_read_cannot_replace_the_same_version_after_a_refresh() {
    let mut state = state_with_preview();
    let old_request = state.version_request;
    let mut changed = entry(2, false);
    changed.checksum = "changed-payload".into();
    assert!(matches!(
        state.update(Message::EntriesRefreshed(Ok(vec![changed]))),
        Outcome::LoadVersion { version: 2, .. }
    ));
    state.update(Message::VersionLoaded {
        version: 2,
        request: old_request,
        result: Err("stale failure".into()),
    });
    assert!(state.error.is_none());
    assert!(state.version_loading);
    assert!(state.detail.is_none());
}
