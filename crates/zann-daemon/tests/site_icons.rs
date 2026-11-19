mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use support::*;
use zann_client::app::local::{ItemsFilter, Page};
use zann_client::browser_ipc::{ErrorCode, Reply, Request};

#[test]
fn icons_are_page_scoped_persistent_and_shared_by_the_desktop_list() {
    let fixture = Fixture::new();
    let host = "keycloak.example.com";
    let url = "https://keycloak.example.com/login";
    let first = fixture.login("First", url);
    let second = fixture.login("Second", url);
    let sibling = fixture.login("Sibling", "https://drone.example.com");
    let daemon = fixture.daemon();
    let mut client = Client::connect(&fixture, &daemon, 1);
    client.pair(&daemon);
    let pixels = vec![126u8; 1024];
    let request = |name: &str, bytes: Option<&[u8]>| Request::SiteIcons {
        captures: BTreeMap::from([(name.to_owned(), bytes.map(|buffer| STANDARD.encode(buffer)))]),
    };
    assert!(matches!(
        client.send(request(host, None)),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
    client.send(query(url));
    assert!(matches!(
        client.send(request("drone.example.com", Some(&pixels))),
        Reply::Error {
            code: ErrorCode::Refused
        }
    ));
    client.send(query(url));
    assert!(
        matches!(client.send(request(host,Some(&pixels))),Reply::SiteIcons {ref icons} if icons.get(host)==Some(&STANDARD.encode(&pixels)))
    );
    client.send(query(url));
    assert!(
        matches!(client.send(request(host,None)),Reply::SiteIcons {ref icons} if icons.get(host)==Some(&STANDARD.encode(&pixels)))
    );
    let page = fixture
        .vault
        .items_list(
            ItemsFilter {
                query: None,
                include_deleted: false,
            },
            Page {
                cursor: None,
                limit: 200,
            },
        )
        .unwrap();
    for id in [first, second] {
        assert_eq!(
            page.items
                .iter()
                .find(|i| i.id == id)
                .unwrap()
                .favicon_rgba
                .as_ref(),
            Some(&pixels)
        );
    }
    assert!(page
        .items
        .iter()
        .find(|i| i.id == sibling)
        .unwrap()
        .favicon_rgba
        .is_none());
}
