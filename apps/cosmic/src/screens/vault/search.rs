//! Native search debounce, pagination and correlated list completions.
use super::*;

impl State {
    pub(super) fn update_search(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::QueryInput(value) => return self.schedule_search(value),

            Message::ClearQuery => return self.schedule_search(String::new()),

            Message::EscapeClearQuery => {
                if self.sync.showing_details {
                    self.sync.showing_details = false;
                    return Outcome::None;
                }
                let search = self.schedule_search(String::new());
                let focus = widget::text_input::focus(self.search_id.clone());
                return match search {
                    Outcome::Task(task) => Outcome::Task(Task::batch([task, focus])),
                    _ => Outcome::Task(focus),
                };
            }

            Message::ListScrolled {
                remaining,
                viewport_height,
            } => {
                if remaining <= viewport_height * PREFETCH_VIEWPORTS {
                    return self.load_more(session);
                }
            }

            Message::SearchReady(generation) => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                let query = self.query.trim().to_string();
                let backend_query = (!query.is_empty()).then(|| query.clone());
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::SearchLoaded {
                        generation,
                        query,
                        result: off_thread(move || local::items(&facade, None, backend_query))
                            .await,
                    }
                }));
            }

            Message::SearchLoaded {
                generation,
                query,
                result,
            } => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                self.searching = false;
                match result {
                    Ok(page) => {
                        self.applied_query = query;
                        self.apply_page(page, true);
                        self.rebuild_nav();
                        self.reconcile_selection();
                        if self.category_needs_prefetch() {
                            return self.load_more(session);
                        }
                    }
                    Err(err) => self.list_error = Some(err),
                }
            }

            Message::LoadMore => {
                return self.load_more(session);
            }

            Message::MoreLoaded { generation, result } => {
                if generation != self.list_generation {
                    return Outcome::None;
                }
                self.busy = false;
                match result {
                    Ok(page) => {
                        self.apply_page(page, false);
                        self.rebuild_nav();
                        self.reconcile_selection();
                        if self.category_needs_prefetch() {
                            return self.load_more(session);
                        }
                    }
                    Err(err) => self.list_error = Some(err),
                }
            }

            _ => unreachable!("only search messages reach this handler"),
        }
        Outcome::None
    }

    fn schedule_search(&mut self, value: String) -> Outcome {
        if self.switching_context
            || self.editor.is_some()
            || self.history.is_some()
            || value == self.query
        {
            return Outcome::None;
        }
        self.busy = false; // Superseded pagination no longer owns the list.
        self.query = value;
        self.reconcile_selection();
        self.list_generation = self.list_generation.wrapping_add(1);
        let generation = self.list_generation;
        self.searching = true;
        self.list_error = None;
        let delay = if self.query.trim().is_empty() {
            Duration::ZERO
        } else {
            SEARCH_DEBOUNCE
        };
        Outcome::Task(cosmic::task::future(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Message::SearchReady(generation)
        }))
    }

    pub(super) fn can_load_more(&self) -> bool {
        self.next_cursor.is_some()
            && !self.busy
            && !self.searching
            && self.editor.is_none()
            && self.history.is_none()
            && self.items.len() < ITEM_CACHE_LIMIT
    }

    fn load_more(&mut self, session: &Session) -> Outcome {
        if !self.can_load_more() {
            return Outcome::None;
        }
        let Some(cursor) = self.next_cursor.clone() else {
            return Outcome::None;
        };
        let facade = session.facade();
        let generation = self.list_generation;
        let query = (!self.applied_query.is_empty()).then(|| self.applied_query.clone());
        self.busy = true;
        Outcome::Task(cosmic::task::future(async move {
            Message::MoreLoaded {
                generation,
                result: off_thread(move || local::items(&facade, Some(cursor), query)).await,
            }
        }))
    }
}
