use std::sync::OnceLock;

use publicsuffix::List;

use crate::SiteUrl;

pub(crate) fn suffixes() -> &'static List {
    static LIST: OnceLock<List> = OnceLock::new();
    LIST.get_or_init(|| {
        List::from_bytes(include_bytes!("../data/public_suffix_list.dat"))
            .expect("digest-pinned PSL must parse")
    })
}

pub(crate) fn equivalent(a: &str, b: &str) -> bool {
    static GROUPS: OnceLock<Vec<Vec<String>>> = OnceLock::new();
    GROUPS
        .get_or_init(|| {
            serde_json::from_str(include_str!("../data/equivalent_domains.json"))
                .expect("digest-pinned equivalences must parse")
        })
        .iter()
        .any(|group| group.iter().any(|d| d == a) && group.iter().any(|d| d == b))
}

pub(crate) fn local_host(site: &SiteUrl) -> bool {
    site.host() == "localhost"
        || site
            .host()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok()
}
