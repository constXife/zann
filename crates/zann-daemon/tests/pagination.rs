mod support;
use support::*;
use zann_client::browser_ipc::{Reply, Request};

#[test]
fn bounded_opaque_cursor_pages_do_not_skip_items_and_cannot_change_origin_or_selection() {
    let fixture = Fixture::new();
    let mut ids = std::collections::BTreeSet::new();
    for n in 0..35 {
        ids.insert(fixture.login(&format!("item-{n}"), "https://example.com"));
    }
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 11);
    client.pair(&daemon);
    let first = client.send(query("https://example.com"));
    let token = match &first {
        Reply::Matches { page } => {
            assert_eq!(page.items.len(), 32);
            let token = page.next_cursor.clone().unwrap();
            assert_eq!(token.len(), 64);
            assert!(!ids.contains(&token));
            for item in &page.items {
                assert!(ids.remove(&item.item_id));
            }
            token
        }
        _ => panic!("expected page"),
    };
    match &client.send(Request::Query {
        context: context("https://example.com"),
        cursor: Some(token),
    }) {
        Reply::Matches { page } => {
            assert_eq!(page.items.len(), 3);
            assert!(page.next_cursor.is_none());
            for item in &page.items {
                assert!(ids.remove(&item.item_id));
            }
        }
        _ => panic!("expected second page"),
    }
    assert!(ids.is_empty());
    let again = client.send(query("https://example.com"));
    let token = match &again {
        Reply::Matches { page } => page.next_cursor.clone().unwrap(),
        _ => panic!("expected cursor"),
    };
    fixture.vault.lock().unwrap();
    fixture.vault.unlock("fixture-password".into()).unwrap();
    assert!(matches!(
        client.send(Request::Query {
            context: context("https://example.com"),
            cursor: Some(token)
        }),
        Reply::Error { .. }
    ));
}
