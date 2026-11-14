use proptest::prelude::*;
use zann_autofill::{AutofillError, LoginMatcher, MatchRules, SiteUrl};

fn site(value: &str) -> SiteUrl {
    SiteUrl::parse(value).unwrap()
}
fn matches(saved: &str, target: &str, rules: MatchRules) -> bool {
    LoginMatcher::new(site(saved), rules)
        .unwrap()
        .matches(&site(target))
}

#[test]
fn canonical_origins_preserve_phishing_boundaries() {
    let saved = site("https://EXAMPLE.com:443/login#part");
    assert_eq!(saved.as_str(), "https://example.com/login");
    assert!(saved.same_origin(&site("https://example.com/other")));
    for target in [
        "http://example.com/",
        "https://example.com:8443/",
        "https://example.com.evil.org/",
        "https://notexample.com/",
    ] {
        assert!(!saved.same_origin(&site(target)), "{target}");
    }
    assert!(site("https://bücher.de").same_origin(&site("https://xn--bcher-kva.de/")));
    assert!(!site("https://apple.com").same_origin(&site("https://аpple.com"))); // Cyrillic а
    for value in [
        "example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,hi",
        "ftp://example.com",
        "https:///example.com",
        "https://@example.com",
        "https://user:password@example.com",
        " https://example.com",
        "https://example.com/\n",
        "https://example.com\\@evil.com",
        "https://example.com.",
        "https://a..example.com",
        "https://a_b.example.com",
    ] {
        assert!(SiteUrl::parse(value).is_err(), "{value}");
    }
    assert!(matches!(
        SiteUrl::parse(&format!("https://example.com/{}", "x".repeat(8192))),
        Err(AutofillError::UrlSize)
    ));
}

#[test]
fn psl_includes_private_wildcard_exception_and_idna_rules() {
    for (url, domain) in [
        ("https://login.example.co.uk", Some("example.co.uk")),
        ("https://co.uk", None),
        ("https://alice.github.io", Some("alice.github.io")),
        ("https://login.alice.github.io", Some("alice.github.io")),
        ("https://a.b.ck", Some("a.b.ck")),
        ("https://b.ck", None),
        ("https://www.ck", Some("www.ck")),
        ("https://sub.www.ck", Some("www.ck")),
        ("https://bücher.de", Some("xn--bcher-kva.de")),
        ("https://127.0.0.1", None),
        ("https://[::1]", None),
        ("https://localhost", None),
    ] {
        assert_eq!(site(url).registrable_domain(), domain, "{url}");
    }
}

#[test]
fn modes_and_ports_have_explicit_scope() {
    let saved = "https://admin.example.com/login?flow=one";
    assert!(matches(
        saved,
        "https://blog.example.com/",
        MatchRules::RegistrableDomain
    ));
    assert!(!matches(
        saved,
        "https://blog.example.com/",
        MatchRules::Host
    ));
    assert!(matches(
        saved,
        "https://admin.example.com/other",
        MatchRules::Host
    ));
    assert!(matches(
        saved,
        "https://admin.example.com/login?flow=one#fragment",
        MatchRules::Exact
    ));
    assert!(!matches(
        saved,
        "https://admin.example.com/login?flow=two",
        MatchRules::Exact
    ));
    for target in [
        "https://evil.com/",
        "https://example.com.evil.com/",
        "http://admin.example.com/login?flow=one",
        "https://admin.example.com:8443/login?flow=one",
    ] {
        for rules in [
            MatchRules::RegistrableDomain,
            MatchRules::Host,
            MatchRules::Exact,
        ] {
            assert!(!matches(saved, target, rules), "{target}");
        }
    }
    for (saved, target) in [
        ("https://foo.co.uk", "https://bar.co.uk"),
        ("https://alice.github.io", "https://bob.github.io"),
        ("https://co.uk", "https://co.uk"),
        ("https://github.io", "https://github.io"),
    ] {
        assert!(!matches(saved, target, MatchRules::RegistrableDomain));
    }
    assert!(!matches(saved, saved, MatchRules::Never));
    assert!(!matches(
        "https://google.com",
        "https://youtube.com",
        MatchRules::RegistrableDomain
    ));
}

#[test]
fn ip_and_localhost_never_expand_to_another_host_or_port() {
    for host in ["127.0.0.1", "[::1]", "localhost"] {
        let url = format!("https://{host}/");
        assert!(matches(&url, &url, MatchRules::RegistrableDomain));
        assert!(!matches(
            &url,
            &format!("https://{host}:8443/"),
            MatchRules::RegistrableDomain
        ));
    }
    assert!(!matches(
        "https://127.0.0.1",
        "https://127.0.0.2",
        MatchRules::RegistrableDomain
    ));
    assert!(!matches(
        "https://localhost",
        "https://evil.localhost",
        MatchRules::RegistrableDomain
    ));
}

#[test]
fn regex_is_full_url_bounded_and_keeps_transport_scope() {
    let matcher = LoginMatcher::new(
        site("https://example.com"),
        MatchRules::Regex {
            pattern: r"https://example\.com/(login|signin)".into(),
        },
    )
    .unwrap();
    assert!(matcher.matches(&site("https://example.com/login")));
    for url in [
        "https://example.com/login/extra",
        "https://evil.com/https://example.com/login",
        "https://example.com.evil.com/login",
        "https://example.com:8443/login",
        "http://example.com/login",
    ] {
        assert!(!matcher.matches(&site(url)), "{url}");
    }
    for pattern in [
        "example)|.*|(?:com".into(),
        "(".into(),
        "".into(),
        "x".repeat(2049),
        r"\w{1000000}".into(),
        format!("{}x{}", "(".repeat(40), ")".repeat(40)),
    ] {
        assert!(MatchRules::Regex { pattern }.validate().is_err());
    }
    let error = MatchRules::Regex {
        pattern: "(private-sentinel".into(),
    }
    .validate()
    .unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-sentinel"));
    assert!(std::error::Error::source(&error).is_some());
}

proptest! {
    #[test]
    fn distinct_registrants_and_sibling_private_sites_never_match(a in "[a-z]{1,20}", b in "[a-z]{1,20}") {
        prop_assume!(a != b);
        for suffix in ["co.uk", "github.io", "com"] {
            let a = format!("https://{a}.{suffix}/");
            let b = format!("https://{b}.{suffix}/");
            prop_assert!(!matches(&a, &b, MatchRules::RegistrableDomain));
        }
    }

    #[test]
    fn arbitrary_untrusted_urls_do_not_panic(input in ".{0,512}") {
        if let Ok(parsed) = SiteUrl::parse(&input) {
            prop_assert_eq!(SiteUrl::parse(parsed.as_str()).unwrap(), parsed.clone());
            let _ = parsed.registrable_domain();
        }
    }
}

#[test]
fn presentation_quality_refines_admitted_matches_without_relaxing_admission() {
    use zann_autofill::MatchQuality;
    let saved = site("https://login.example.com/login");
    let matcher = LoginMatcher::new(saved.clone(), MatchRules::RegistrableDomain).unwrap();
    for (target, expected) in [
        ("https://login.example.com/login", Some(MatchQuality::Exact)),
        (
            "https://login.example.com/other",
            Some(MatchQuality::Origin),
        ),
        (
            "https://other.example.com/login",
            Some(MatchQuality::Domain),
        ),
        ("https://example.com.evil.test/login", None),
        ("http://login.example.com/login", None),
        ("https://login.example.com:8443/login", None),
    ] {
        let target = site(target);
        assert_eq!(matcher.match_quality(&target), expected);
        assert_eq!(matcher.matches(&target), expected.is_some());
    }
    assert_eq!(
        LoginMatcher::new(saved.clone(), MatchRules::Never)
            .unwrap()
            .match_quality(&saved),
        None
    );
    let regex = LoginMatcher::new(
        saved,
        MatchRules::Regex {
            pattern: "https://other\\.test/login".into(),
        },
    )
    .unwrap();
    assert_eq!(
        regex.match_quality(&site("https://other.test/login")),
        Some(MatchQuality::Pattern)
    );
    let equivalent =
        LoginMatcher::new(site("https://google.com"), MatchRules::RegistrableDomain).unwrap();
    assert_eq!(
        equivalent.match_quality(&site("https://youtube.com")),
        None, // The vendored equivalent-domain registry is currently empty.
    );
}
