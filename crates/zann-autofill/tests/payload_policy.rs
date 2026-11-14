use zann_autofill::*;
use zann_core::secrets::{EncryptedPayload, FieldKind, FieldValue};

fn field(value: &str) -> FieldValue {
    FieldValue {
        kind: FieldKind::Text,
        value: value.into(),
        meta: None,
    }
}
fn payload() -> EncryptedPayload {
    let mut payload = EncryptedPayload::new("login");
    payload.fields.insert(
        "url".into(),
        FieldValue {
            kind: FieldKind::Url,
            value: "https://example.com/login".into(),
            meta: None,
        },
    );
    payload
}

#[test]
fn absent_rules_alone_get_the_documented_default_and_strict_rules_roundtrip() {
    assert_eq!(
        MatchRules::from_field(None).unwrap(),
        MatchRules::RegistrableDomain
    );
    for rules in [
        MatchRules::RegistrableDomain,
        MatchRules::Host,
        MatchRules::Exact,
        MatchRules::Never,
        MatchRules::Regex {
            pattern: "https://example.com/.*".into(),
        },
    ] {
        assert_eq!(MatchRules::from_field(Some(&rules.field())).unwrap(), rules);
    }
    for json in [
        "",
        "null",
        "[]",
        "{}",
        r#"{"mode":"future"}"#,
        r#"{"mode":"host","extra":1}"#,
        r#"{"mode":"host","pattern":"ignored"}"#,
        r#"{"mode":"host","pattern":null}"#,
        r#"{"mode":"host","mode":"registrable-domain"}"#,
        r#"{"mode":"regex"}"#,
        r#"{"mode":"regex","pattern":"a","pattern":"b"}"#,
    ] {
        assert!(
            MatchRules::from_field(Some(&field(json))).is_err(),
            "{json}"
        );
    }
    assert!(MatchRules::from_field(Some(&field(&" ".repeat(4097)))).is_err());
    let mut wrong_kind = MatchRules::Host.field();
    wrong_kind.kind = FieldKind::Password;
    assert!(MatchRules::from_field(Some(&wrong_kind)).is_err());
}

#[test]
fn payload_rules_fail_closed_and_only_logins_with_typed_urls_are_candidates() {
    let mut payload = payload();
    let target = SiteUrl::parse("https://sub.example.com").unwrap();
    assert!(LoginMatcher::from_payload(&payload)
        .unwrap()
        .matches(&target));
    payload
        .fields
        .insert(MATCH_RULES_KEY.into(), MatchRules::Never.field());
    assert!(!LoginMatcher::from_payload(&payload)
        .unwrap()
        .matches(&target));
    payload
        .fields
        .insert(MATCH_RULES_KEY.into(), field("malformed-sentinel"));
    assert!(LoginMatcher::from_payload(&payload).is_err());
    payload.fields.remove(MATCH_RULES_KEY);
    payload.fields.get_mut("url").unwrap().kind = FieldKind::Text;
    assert!(LoginMatcher::from_payload(&payload).is_err());
    payload.fields.get_mut("url").unwrap().kind = FieldKind::Url;
    payload.type_id = "api".into();
    assert!(LoginMatcher::from_payload(&payload).is_err());
}

#[test]
fn admission_requires_gesture_secure_same_origin_frame_and_match() {
    let matcher = LoginMatcher::from_payload(&payload()).unwrap();
    let top = SiteUrl::parse("https://example.com").unwrap();
    let frame = SiteUrl::parse("https://example.com/form").unwrap();
    let mut context = FillContext {
        top_level: &top,
        frame: &frame,
        gesture: UserGesture::Absent,
    };
    assert_eq!(authorize_fill(&matcher, &context), Err(FillDenied::Gesture));
    context.gesture = UserGesture::Explicit;
    assert_eq!(authorize_fill(&matcher, &context), Ok(()));
    for url in [
        "https://login.example.com/form",
        "https://example.com:8443",
        "http://example.com",
        "https://evil.org",
    ] {
        let foreign = SiteUrl::parse(url).unwrap();
        assert_eq!(
            authorize_fill(
                &matcher,
                &FillContext {
                    frame: &foreign,
                    ..context
                }
            ),
            Err(FillDenied::CrossOriginFrame)
        );
    }
    let foreign = SiteUrl::parse("https://evil.org").unwrap();
    assert_eq!(
        authorize_fill(
            &matcher,
            &FillContext {
                top_level: &foreign,
                frame: &foreign,
                ..context
            }
        ),
        Err(FillDenied::NoMatch)
    );
    let insecure = SiteUrl::parse("http://example.com").unwrap();
    let insecure_matcher = LoginMatcher::new(insecure.clone(), MatchRules::Host).unwrap();
    assert_eq!(
        authorize_fill(
            &insecure_matcher,
            &FillContext {
                top_level: &insecure,
                frame: &insecure,
                ..context
            }
        ),
        Err(FillDenied::InsecureTransport)
    );
}
