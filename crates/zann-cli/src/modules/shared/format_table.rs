use crate::modules::shared::SharedItemResponse;

pub(crate) fn print_list_table(items: &[SharedItemResponse]) {
    let mut rows = Vec::new();
    let mut path_width = "PATH".len();

    for item in items {
        let keys = match item.payload.as_ref() {
            Some(payload) => {
                let mut list: Vec<&String> = payload.fields.keys().collect();
                list.sort();
                let joined = list
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", joined)
            }
            None => "[encrypted]".to_string(),
        };
        path_width = path_width.max(item.path.len());
        rows.push((item.path.as_str(), keys));
    }

    println!("{:<path_width$}  KEYS", "PATH", path_width = path_width);
    for (path, keys) in rows {
        println!("{:<path_width$}  {}", path, keys, path_width = path_width);
    }
}
