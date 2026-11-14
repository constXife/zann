#![cfg(feature = "browser-ipc")]
use zann_client::browser_ipc::{
    BrowserContext, BrowserMatch, BrowserScope, LoginSearch, MatchPage, Request, SearchError,
};

fn context() -> BrowserContext {
    BrowserContext {
        top_level_url: "https://example.test/login".into(),
        frame_url: "https://example.test/login".into(),
    }
}
fn scope() -> BrowserScope {
    BrowserScope {
        storage_id: "storage".into(),
        vault_id: "vault".into(),
        generation: 1,
    }
}
fn item(id: usize) -> BrowserMatch {
    BrowserMatch {
        item_id: id.to_string(),
        title: format!("Login {id}"),
        username: None,
        match_quality: zann_autofill::MatchQuality::Origin,
    }
}
fn page(items: Vec<BrowserMatch>, cursor: Option<usize>) -> MatchPage {
    MatchPage {
        items,
        scope: scope(),
        next_cursor: cursor.map(|n| format!("{n:064x}")),
    }
}

#[test]
fn searches_past_empty_and_matching_pages_and_publishes_only_the_complete_unique_result() {
    let mut search = LoginSearch::new(context()).unwrap();
    for (index, response) in [
        page(vec![], Some(1)),
        page(vec![item(1)], Some(2)),
        page(vec![item(1), item(2)], None),
    ]
    .into_iter()
    .enumerate()
    {
        let Request::Query {
            context: actual,
            cursor,
        } = search.request(index as f64).unwrap()
        else {
            panic!("query only");
        };
        assert!(actual == context());
        assert_eq!(cursor, (index > 0).then(|| format!("{index:064x}")));
        assert_eq!(
            search.accept_page(response, index as f64).unwrap(),
            index == 2
        );
    }
    let result = search.take_result(3.0).unwrap();
    assert_eq!(
        result
            .items
            .iter()
            .map(|i| i.item_id.as_str())
            .collect::<Vec<_>>(),
        ["1", "2"]
    );
    assert!(result.scope == scope());
    assert!(search.take_result(4.0).is_err());
}

#[test]
fn scope_changes_cursor_loops_and_conflicting_metadata_poison_partial_searches() {
    for change in 0..3 {
        let mut search = LoginSearch::new(context()).unwrap();
        search.request(0.0).unwrap();
        search
            .accept_page(page(vec![item(1)], Some(1)), 0.0)
            .unwrap();
        search.request(1.0).unwrap();
        let mut next = page(vec![item(1)], Some(2));
        let expected = match change {
            0 => {
                next.scope.generation += 1;
                SearchError::SelectionChanged
            }
            1 => {
                next.next_cursor = Some(format!("{:064x}", 1));
                SearchError::Protocol
            }
            _ => {
                next.items[0].title = "changed".into();
                SearchError::Protocol
            }
        };
        assert_eq!(search.accept_page(next, 1.0), Err(expected));
        assert!(search.take_result(2.0).is_err());
        assert!(search.request(2.0).is_err());
    }
}

#[test]
fn deadlines_invalid_clocks_and_incomplete_searches_never_publish_partial_results() {
    for elapsed in [30_000.0, f64::INFINITY, f64::NAN, -1.0] {
        let mut search = LoginSearch::new(context()).unwrap();
        search.request(0.0).unwrap();
        assert!(search
            .accept_page(page(vec![item(1)], None), elapsed)
            .is_err());
        assert!(search.take_result(0.0).is_err());
    }
    let mut search = LoginSearch::new(context()).unwrap();
    search.request(0.0).unwrap();
    search
        .accept_page(page(vec![item(1)], Some(1)), 0.0)
        .unwrap();
    assert_eq!(search.request(30_000.0).err(), Some(SearchError::Timeout));
    assert!(search.take_result(0.0).is_err());
    let mut search = LoginSearch::new(context()).unwrap();
    search.request(0.0).unwrap();
    assert!(search.take_result(0.0).is_err());
}

#[test]
fn bounds_pages_matches_and_page_cardinality_without_truncation() {
    let mut search = LoginSearch::new(context()).unwrap();
    for n in 1..=4096 {
        search.request(0.0).unwrap();
        let result = search.accept_page(page(vec![], Some(n)), 0.0);
        if n == 4096 {
            assert_eq!(result, Err(SearchError::Limit));
        } else {
            assert_eq!(result, Ok(false));
        }
    }
    assert!(search.take_result(0.0).is_err());
    let mut search = LoginSearch::new(context()).unwrap();
    for n in 0..256 {
        search.request(0.0).unwrap();
        search
            .accept_page(
                page((n * 32..n * 32 + 32).map(item).collect(), Some(n + 1)),
                0.0,
            )
            .unwrap();
    }
    search.request(0.0).unwrap();
    assert_eq!(
        search.accept_page(page(vec![item(8192)], None), 0.0),
        Err(SearchError::Limit)
    );
    assert!(search.take_result(0.0).is_err());
    let mut search = LoginSearch::new(context()).unwrap();
    search.request(0.0).unwrap();
    assert_eq!(
        search.accept_page(page((0..33).map(item).collect(), None), 0.0),
        Err(SearchError::Protocol)
    );
}
