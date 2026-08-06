//! The command palette.
//!
//! The same shape the desktop app has: a query, the commands that match it,
//! then the items that do. It owns nothing but the query and where the
//! highlight sits — the commands are named by the shell, which is the only
//! thing that can carry them out, and the items are borrowed from the vault.

use cosmic::iced::{Alignment, Length};
use cosmic::{theme, widget, Element};

use crate::i18n::t;

/// What the palette can ask for. Everything here is the shell's to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Lock,
    RevealAll,
    CopyPrimary,
    Settings,
}

impl Command {
    /// In the desktop app's order, which puts the destructive one first because
    /// it is the one people come to the palette for.
    const ALL: &'static [Self] = &[
        Self::Lock,
        Self::RevealAll,
        Self::CopyPrimary,
        Self::Settings,
    ];

    fn label(self) -> String {
        t(match self {
            Self::Lock => "palette.lock",
            Self::RevealAll => "palette.revealAll",
            Self::CopyPrimary => "palette.copyPrimary",
            Self::Settings => "palette.openSettings",
        })
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Lock => "Ctrl+L",
            Self::RevealAll => "Ctrl+R",
            Self::CopyPrimary => "Ctrl+C",
            Self::Settings => "Ctrl+,",
        }
    }

    /// Whether it can do anything right now. The two that act on an item are
    /// shown greyed rather than hidden, so the list does not jump about as the
    /// selection changes.
    fn enabled(self, has_item: bool) -> bool {
        match self {
            Self::RevealAll | Self::CopyPrimary => has_item,
            Self::Lock | Self::Settings => true,
        }
    }
}

/// One row of the palette, once the query has been applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    Command(Command),
    /// An item, by id — the palette never holds a secret, only a way back to
    /// the one the vault already has.
    Item(String),
}

pub struct State {
    query: String,
    /// Which row the arrows are on. Kept in range by [`State::rows`] every time
    /// the query changes, because a shorter list can leave it past the end.
    cursor: usize,
}

#[derive(Clone, Debug)]
pub enum Message {
    QueryInput(String),
    /// A row was clicked, or Enter was pressed on it.
    Run(Row),
    Move(isize),
    Submit,
    Close,
}

pub enum Outcome {
    None,
    Run(Row),
    Close,
}

/// What the vault hands the palette to draw: an item's id and how to name it.
///
/// Owned rather than borrowed, because the palette is drawn from `dialog`,
/// which builds the list on the spot and cannot hand back a view that points
/// into it.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub path: String,
}

/// How many items the palette offers. The desktop app shows the same eight:
/// the palette is for reaching one thing quickly, not for browsing.
const ITEM_LIMIT: usize = 8;

impl State {
    pub fn new() -> Self {
        Self {
            query: String::new(),
            cursor: 0,
        }
    }

    pub fn update(&mut self, message: Message, rows: &[Row]) -> Outcome {
        match message {
            Message::QueryInput(value) => {
                self.query = value;
                self.cursor = 0;
                Outcome::None
            }
            Message::Move(by) => {
                if !rows.is_empty() {
                    let len = rows.len() as isize;
                    let next = (self.cursor as isize + by).rem_euclid(len);
                    self.cursor = next as usize;
                }
                Outcome::None
            }
            Message::Submit => match rows.get(self.cursor) {
                Some(row) => Outcome::Run(row.clone()),
                None => Outcome::None,
            },
            Message::Run(row) => Outcome::Run(row),
            Message::Close => Outcome::Close,
        }
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    /// The rows the current query leaves, commands first. Also clamps the
    /// highlight, which is why it takes `&self` and is called before drawing.
    pub fn rows(&self, candidates: &[Candidate], has_item: bool) -> Vec<Row> {
        let needle = self.query.trim().to_lowercase();
        let matches =
            |haystack: &str| needle.is_empty() || haystack.to_lowercase().contains(needle.as_str());

        let mut rows: Vec<Row> = Command::ALL
            .iter()
            .filter(|command| command.enabled(has_item) && matches(&command.label()))
            .map(|command| Row::Command(*command))
            .collect();

        rows.extend(
            candidates
                .iter()
                .filter(|item| matches(&item.title) || matches(&item.path))
                .take(ITEM_LIMIT)
                .map(|item| Row::Item(item.id.clone())),
        );
        rows
    }

    /// Takes its data by value: what it draws is built for this frame and the
    /// widgets keep it, so nothing here points back at the caller's stack.
    pub fn view(&self, rows: Vec<Row>, candidates: Vec<Candidate>) -> Element<'static, Message> {
        let spacing = theme::spacing();
        let cursor = self.cursor.min(rows.len().saturating_sub(1));
        let empty = rows.is_empty();

        let mut list = widget::column::with_capacity(rows.len()).spacing(spacing.space_xxxs);
        for (index, row) in rows.into_iter().enumerate() {
            let (label, hint) = match &row {
                Row::Command(command) => (command.label(), command.hint().to_string()),
                Row::Item(id) => match candidates.iter().find(|item| &item.id == id) {
                    Some(item) => (item.title.clone(), item.path.clone()),
                    None => continue,
                },
            };

            list = list.push(
                widget::button::custom(
                    widget::row::with_capacity(2)
                        .push(widget::text::body(label).width(Length::Fill))
                        .push(widget::text::caption(hint))
                        .spacing(spacing.space_xs)
                        .align_y(Alignment::Center),
                )
                .class(if index == cursor {
                    theme::Button::Suggested
                } else {
                    theme::Button::Text
                })
                .width(Length::Fill)
                .padding([spacing.space_xxxs, spacing.space_xs])
                .on_press(Message::Run(row)),
            );
        }

        if empty {
            list = list.push(widget::text::body(t("items.kvNoMatches")));
        }

        let body = widget::column::with_capacity(2)
            .push(
                widget::text_input::search_input(t("common.command"), self.query.clone())
                    .on_input(Message::QueryInput)
                    .on_submit(|_| Message::Submit)
                    .width(Length::Fill),
            )
            .push(widget::scrollable(list).height(Length::Fixed(320.0)))
            .spacing(spacing.space_s);

        widget::dialog()
            .title(t("common.command"))
            .control(body)
            .secondary_action(widget::button::standard(t("common.close")).on_press(Message::Close))
            .into()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
