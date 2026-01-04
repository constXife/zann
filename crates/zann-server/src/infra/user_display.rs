pub fn display_name_for_user(full_name: Option<&str>, email: &str) -> String {
    let name = full_name.map(str::trim).filter(|value| !value.is_empty());
    name.map(str::to_string)
        .unwrap_or_else(|| email.to_string())
}

pub fn avatar_initials_for_user(full_name: Option<&str>, email: &str) -> String {
    if let Some(name) = full_name.map(str::trim).filter(|value| !value.is_empty()) {
        let mut initials = String::new();
        for part in name.split_whitespace() {
            if let Some(ch) = part.chars().next() {
                initials.push(ch);
            }
            if initials.chars().count() >= 2 {
                break;
            }
        }
        if !initials.is_empty() {
            return initials.to_uppercase();
        }
    }

    let local = email.split('@').next().unwrap_or(email).trim();
    let mut initials = String::new();
    for ch in local.chars() {
        if ch.is_ascii_alphanumeric() {
            initials.push(ch);
        }
        if initials.len() >= 2 {
            break;
        }
    }
    if initials.is_empty() {
        initials.push('U');
    }
    initials.to_uppercase()
}
