use zann_ui_core::login_list::{LoginList, LoginListItem};

struct Login {
    id: usize,
    title: String,
    username: Option<String>,
}
impl LoginListItem for Login {
    fn title(&self) -> &str {
        &self.title
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}
fn login(id: usize, title: &str, username: Option<&str>) -> Login {
    Login {
        id,
        title: title.into(),
        username: username.map(str::to_owned),
    }
}

#[test]
fn public_title_and_username_filter_is_case_insensitive_trimmed_and_keeps_rank_order() {
    let mut list = LoginList::new(vec![
        login(3, "Рабочий аккаунт", Some("User@Example.test")),
        login(1, "Другой рабочий", None),
        login(2, "Personal", Some("alice")),
    ]);
    assert_eq!(list.filter("  РАБОЧИЙ  ").unwrap(), 2);
    assert_eq!(
        list.window(0, 2)
            .unwrap()
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        [3, 1]
    );
    assert_eq!(list.filter("USER@EXAMPLE").unwrap(), 1);
    assert_eq!(list.window(0, 1).unwrap()[0].id, 3);
    assert_eq!(list.filter("missing").unwrap(), 0);
    assert!(list.is_empty());
    assert!(list.window(0, 20).unwrap().is_empty());
    assert!(list.window(1, 20).is_none());
    assert_eq!(list.filter(" \t ").unwrap(), 3);
    assert_eq!(list.total(), 3);
    assert_eq!(
        list.window(1, 10)
            .unwrap()
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn distant_indices_and_bounded_windows_map_back_to_the_original_items() {
    let mut list = LoginList::new(
        (0..8192)
            .map(|id| {
                login(
                    id,
                    &format!("Account {id:04}"),
                    Some(&format!("user-{id:04}@example.test")),
                )
            })
            .collect(),
    );
    assert_eq!(list.total(), 8192);
    assert_eq!(
        list.window(8190, 64)
            .unwrap()
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        [8190, 8191]
    );
    assert_eq!(list.filter("user-7000@").unwrap(), 1);
    assert_eq!(list.window(0, 1).unwrap()[0].id, 7000);
    assert!(list.filter(&"x".repeat(257)).is_err());
    assert_eq!(
        list.window(0, 1).unwrap()[0].id,
        7000,
        "rejected queries do not mutate selection data"
    );
    assert_eq!(list.filter("").unwrap(), 8192);
    assert_eq!(list.window(7000, 1).unwrap()[0].id, 7000);
}
