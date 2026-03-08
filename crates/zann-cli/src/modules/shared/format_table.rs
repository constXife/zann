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

    println!("{:<path_width$}  KEYS", "PATH", path_width = path_width);
    for (path, keys) in rows {
        println!("{:<path_width$}  {}", path, keys, path_width = path_width);
    }
}
