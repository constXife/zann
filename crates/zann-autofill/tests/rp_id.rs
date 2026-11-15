use zann_autofill::{CrossOriginPermission as Permission, RpId, SiteUrl};

#[test]
fn rp_ids_are_canonical_domains_and_never_suffix_or_ip_aliases() {
    for valid in [
        "example.com",
        "login.example.com",
        "foo.github.io",
        "localhost",
        "xn--bcher-kva.example",
    ] {
        assert!(RpId::parse(valid).is_ok(), "{valid}");
    }
    for invalid in [
        "",
        "com",
        "co.uk",
        "github.io",
        "127.0.0.1",
        "[::1]",
        "EXAMPLE.com",
        "example.com.",
        "https://example.com",
        "example.com:443",
        "example.com/path",
        "example.com?x",
        "user@example.com",
        "a..com",
        "-a.com",
    ] {
        assert!(RpId::parse(invalid).is_err(), "{invalid}");
    }
    let rp = RpId::parse("example.com").unwrap();
    for host in ["https://example.com", "https://a.example.com"] {
        let site = SiteUrl::parse(host).unwrap();
        rp.authorize(&site, &site, Permission::Denied)
            .expect("exact / label suffix");
    }
    for host in [
        "https://evilexample.com",
        "https://example.com.evil.test",
        "http://example.com",
    ] {
        let site = SiteUrl::parse(host).unwrap();
        assert!(rp.authorize(&site, &site, Permission::Denied).is_err());
    }
}

#[test]
fn cross_origin_frames_require_browser_authority_and_bind_the_requesting_frame() {
    let rp = RpId::parse("example.com").unwrap();
    let top = SiteUrl::parse("https://container.test").unwrap();
    let frame = SiteUrl::parse("https://login.example.com").unwrap();
    assert!(rp.authorize(&top, &frame, Permission::Denied).is_err());
    assert!(rp
        .authorize(&top, &frame, Permission::GrantedByBrowser)
        .is_ok());
    assert!(rp
        .authorize(&frame, &top, Permission::GrantedByBrowser)
        .is_err());
    let insecure = SiteUrl::parse("http://container.test").unwrap();
    assert!(rp
        .authorize(&insecure, &frame, Permission::GrantedByBrowser)
        .is_err());
}
