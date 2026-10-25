//! Native editor/history effects and correlated completion routing.
use super::*;

impl State {
    pub(super) fn update_editing(&mut self, message: Message, session: &Session) -> Outcome {
        match &message {
            Message::Saved(id, _) if *id != self.editing_generation || self.editor.is_none() => {
                return Outcome::None
            }
            Message::RefreshedAfterSave(id, list, _)
                if *id != self.editing_generation || *list != self.list_generation =>
            {
                return Outcome::None
            }
            _ => {}
        }
        let generation = self.editing_generation;
        match message {
            Message::OpenCreate => {
                if self.busy || self.searching || self.editor.is_some() || self.history.is_some() {
                    return Outcome::None;
                }
                match editor::State::create(self.preferred_create_type()) {
                    Ok(editor) => {
                        self.editor = Some(editor);
                        self.editing_generation = crate::backend::next_view_request();
                    }
                    Err(error) => self.error = Some(error),
                }
            }

            Message::OpenEdit => {
                if self.busy || self.searching || self.editor.is_some() || self.history.is_some() {
                    return Outcome::None;
                }
                if let Some(detail) = self.detail.as_ref() {
                    match editor::State::edit(detail) {
                        Ok(editor) => {
                            self.editor = Some(editor);
                            self.editing_generation = crate::backend::next_view_request();
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
            }

            Message::OpenHistory => {
                if self.busy || self.searching || self.editor.is_some() || self.history.is_some() {
                    return Outcome::None;
                }
                let Some(detail) = self.detail.as_ref() else {
                    return Outcome::None;
                };
                let state = history::State::new(detail);
                let item_id = state.item_id().to_string();
                self.editing_generation = crate::backend::next_view_request();
                let generation = self.editing_generation;
                self.history = Some(state);
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::HistoryResponse(
                        generation,
                        history::Message::EntriesLoaded(
                            off_thread(move || local::item_history(&facade, item_id)).await,
                        ),
                    )
                }));
            }

            Message::Editor(message) => {
                let reveal_toggled = matches!(&message, editor::Message::ToggleReveal(_));
                let Some(editor) = self.editor.as_mut() else {
                    return Outcome::None;
                };
                match editor.update(message) {
                    editor::Outcome::None => {
                        if reveal_toggled && self.reveal_seconds > 0 {
                            self.reveal_generation = self.reveal_generation.wrapping_add(1);
                            let generation = self.reveal_generation;
                            let seconds = u64::from(self.reveal_seconds);
                            return Outcome::Task(cosmic::task::future(async move {
                                tokio::time::sleep(Duration::from_secs(seconds)).await;
                                Message::HideRevealed(generation)
                            }));
                        }
                    }
                    editor::Outcome::Cancel => self.editor = None,
                    editor::Outcome::Submit(request) => {
                        let facade = session.facade();
                        return Outcome::Task(cosmic::task::future(async move {
                            let saved = off_thread(move || match request {
                                SaveRequest::Create(item) => local::item_create(&facade, item),
                                SaveRequest::Update { id, item } => {
                                    local::item_update(&facade, id, item)
                                }
                            })
                            .await
                            .and_then(Detail::parse);
                            Message::Saved(generation, saved)
                        }));
                    }
                }
            }

            Message::HistoryResponse(generation, message) => {
                if generation == self.editing_generation && self.history.is_some() {
                    return self.update(Message::History(message), session);
                }
            }

            Message::History(message) => {
                let Some(history) = self.history.as_mut() else {
                    return Outcome::None;
                };
                let generation = self.editing_generation;
                let reveal_toggled = matches!(
                    &message,
                    history::Message::Detail(detail::Message::ToggleReveal(_))
                );
                match history.update(message) {
                    history::Outcome::None => {
                        if reveal_toggled && self.reveal_seconds > 0 {
                            self.reveal_generation = self.reveal_generation.wrapping_add(1);
                            let generation = self.reveal_generation;
                            let seconds = u64::from(self.reveal_seconds);
                            return Outcome::Task(cosmic::task::future(async move {
                                tokio::time::sleep(Duration::from_secs(seconds)).await;
                                Message::HideRevealed(generation)
                            }));
                        }
                    }
                    history::Outcome::LoadVersion(version) => {
                        let item_id = history.item_id().to_string();
                        let facade = session.facade();
                        return Outcome::Task(cosmic::task::future(async move {
                            Message::HistoryResponse(
                                generation,
                                history::Message::VersionLoaded {
                                    version,
                                    result: off_thread(move || {
                                        local::item_history_get(&facade, item_id, version)
                                    })
                                    .await,
                                },
                            )
                        }));
                    }
                    history::Outcome::Restore(version) => {
                        let item_id = history.item_id().to_string();
                        let facade = session.facade();
                        return Outcome::Task(cosmic::task::future(async move {
                            Message::HistoryResponse(
                                generation,
                                history::Message::Restored(
                                    off_thread(move || {
                                        local::item_history_restore(&facade, item_id, version)
                                    })
                                    .await
                                    .and_then(Detail::parse),
                                ),
                            )
                        }));
                    }
                    history::Outcome::Restored(detail) => {
                        self.history = None;
                        self.detail = Some(detail);
                        self.query.clear();
                        self.applied_query.clear();
                        self.list_generation = self.list_generation.wrapping_add(1);
                        self.searching = false;
                        self.error = None;
                        let facade = session.facade();
                        let list_generation = self.list_generation;
                        let refresh_items = cosmic::task::future(async move {
                            Message::RefreshedAfterSave(
                                generation,
                                list_generation,
                                off_thread(move || local::items(&facade, None, None)).await,
                            )
                        });
                        return Outcome::Task(Task::batch([
                            refresh_items,
                            Self::load_vaults(session),
                        ]));
                    }
                    history::Outcome::Copy(value) => {
                        return Outcome::Copy {
                            value,
                            feedback: Task::none(),
                        };
                    }
                    history::Outcome::Close => self.history = None,
                }
            }

            Message::Saved(_, Ok(detail)) => {
                self.editor = None;
                self.detail = Some(detail);
                self.query.clear();
                self.applied_query.clear();
                self.list_generation = self.list_generation.wrapping_add(1);
                self.searching = false;
                self.error = None;
                let facade = session.facade();
                let list_generation = self.list_generation;
                let refresh_items = cosmic::task::future(async move {
                    Message::RefreshedAfterSave(
                        generation,
                        list_generation,
                        off_thread(move || local::items(&facade, None, None)).await,
                    )
                });
                return Outcome::Task(Task::batch([refresh_items, Self::load_vaults(session)]));
            }

            Message::Saved(_, Err(err)) => {
                if let Some(editor) = self.editor.as_mut() {
                    editor.set_error(err);
                }
            }

            Message::RefreshedAfterSave(_, _, Ok(page)) => {
                self.apply_page(page, true);
                self.rebuild_nav();
            }

            Message::RefreshedAfterSave(_, _, Err(err)) => {
                // The write already succeeded, so keep the new detail visible
                // and report only the failed list refresh.
                self.error = Some(err);
            }

            _ => unreachable!("only editing messages reach this handler"),
        }
        Outcome::None
    }
}
