pub mod tokens;

#[derive(Debug, Clone)]
pub enum RunMode {
    Server,
    Migrate,
    Tokens(Vec<String>),
    OpenApi { out: Option<String> },
}

pub fn parse_args() -> RunMode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("migrate") => RunMode::Migrate,
        Some("tokens") => RunMode::Tokens(args.iter().skip(1).cloned().collect()),
        Some("openapi") => {
            let mut out = None;
            let mut iter = args.iter().skip(1);
            while let Some(arg) = iter.next() {
                if arg == "--out" || arg == "-o" {
                    out = iter.next().cloned();
                }
            }
            RunMode::OpenApi { out }
        }
        _ => RunMode::Server,
    }
}
