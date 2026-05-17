use crate::modules::shared::{payload_or_error, SharedItemResponse};

pub(crate) fn print_list_table(items: &[SharedItemResponse]) {
    let mut rows = Vec::new();
    let mut path_width = "PATH".len();

    for item in items {
        let keys = match payload_or_error(item) {
            Ok(payload) => {
                let mut list: Vec<&String> = payload.fields.keys().collect();
                list.sort();
                let joined = list
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", joined)
            }
            Err(_) => "[encrypted]".to_string(),
        };
        path_width = path_width.max(item.path.len());
        rows.push((item.path.as_str(), keys));
    }

    rows.sort_by(|a, b| {
        let depth_a = a.0.matches('/').count();
        let depth_b = b.0.matches('/').count();
        depth_a.cmp(&depth_b).then_with(|| a.0.cmp(b.0))
    });

    println!("{:<path_width$}  KEYS", "PATH", path_width = path_width);
    for (path, keys) in rows {
        println!("{:<path_width$}  {}", path, keys, path_width = path_width);
    }
}
