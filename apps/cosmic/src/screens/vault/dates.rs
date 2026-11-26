//! Calendar-day selection for the local vault list.
use super::{t, widget, Element, Message};
use crate::i18n::short_date;
use cosmic::widget::calendar::CalendarModel;
use jiff::civil::{Date, Weekday};
use jiff::tz::TimeZone;
use zann_core::UpdatedRange;

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Toggle,
    From,
    Through,
    PreviousMonth,
    NextMonth,
    Select(Date),
    Apply,
    Clear,
}

#[derive(Clone, Copy)]
struct Days {
    from: Date,
    through: Date,
}

impl Days {
    fn range(self, zone: TimeZone) -> Result<Option<UpdatedRange>, jiff::Error> {
        let start = self.from.to_zoned(zone.clone())?;
        let end = self.through.tomorrow()?.to_zoned(zone)?;
        Ok(UpdatedRange::from_unix_seconds(
            start.timestamp().as_second(),
            end.timestamp().as_second(),
        ))
    }
}

struct Editor {
    days: Days,
    calendar: CalendarModel,
    picking_from: bool,
}

#[derive(Default)]
pub(super) struct Filter {
    active: Option<(Days, UpdatedRange)>,
    editor: Option<Editor>,
}

impl Filter {
    pub(super) fn range(&self) -> Option<UpdatedRange> {
        self.active.map(|(_, range)| range)
    }

    pub(super) fn update(&mut self, action: Action) -> Result<(), jiff::Error> {
        match action {
            Action::Toggle if self.editor.is_none() => {
                let today = jiff::Timestamp::now()
                    .to_zoned(TimeZone::try_system()?)
                    .date();
                let days = self.active.map(|(days, _)| days).unwrap_or(Days {
                    from: today,
                    through: today,
                });
                self.editor = Some(Editor {
                    days,
                    calendar: CalendarModel::new(days.from, days.from),
                    picking_from: true,
                });
            }
            Action::Toggle => self.editor = None,
            Action::Clear => *self = Self::default(),
            _ => {
                let Some(editor) = &mut self.editor else {
                    return Ok(());
                };
                match action {
                    Action::From | Action::Through => {
                        editor.picking_from = matches!(action, Action::From);
                        editor
                            .calendar
                            .set_selected_visible(if editor.picking_from {
                                editor.days.from
                            } else {
                                editor.days.through
                            });
                    }
                    Action::Select(day) => {
                        if editor.picking_from {
                            editor.days.from = day;
                            if day > editor.days.through {
                                editor.days.through = day;
                            }
                            editor.picking_from = false;
                            editor.calendar.set_selected_visible(editor.days.through);
                        } else {
                            editor.days.through = day;
                            editor.calendar.set_selected_visible(day);
                        }
                    }
                    Action::PreviousMonth => editor.calendar.show_prev_month(),
                    Action::NextMonth => editor.calendar.show_next_month(),
                    Action::Apply => {
                        if let Some(range) = editor.days.range(TimeZone::try_system()?)? {
                            self.active = Some((editor.days, range));
                            self.editor = None;
                        }
                    }
                    Action::Toggle | Action::Clear => unreachable!(),
                }
            }
        }
        Ok(())
    }

    pub(super) fn view(&self) -> Element<'_, Message> {
        let msg = Message::DateFilter;
        let mut label = t("items.updatedRange");
        if let Some((days, _)) = self.active {
            let from = short_date(days.from);
            label = if days.from == days.through {
                format!("{label} · {from}")
            } else {
                format!("{label} · {from} – {}", short_date(days.through))
            };
        }
        let mut row = widget::row::with_capacity(2)
            .push(widget::button::text(label).on_press(msg(Action::Toggle)));
        if self.active.is_some() {
            row =
                row.push(widget::button::text(t("items.clearDates")).on_press(msg(Action::Clear)));
        }
        let mut column = widget::column::with_capacity(4).push(row);
        if let Some(editor) = &self.editor {
            let day_button = |key, date, action, selected| {
                let label = format!("{} {date}", t(key));
                let button = if selected {
                    widget::button::suggested(label)
                } else {
                    widget::button::standard(label)
                };
                button.on_press(msg(action))
            };
            column = column
                .push(
                    widget::row::with_capacity(2)
                        .push(day_button(
                            "items.dateFrom",
                            short_date(editor.days.from),
                            Action::From,
                            editor.picking_from,
                        ))
                        .push(day_button(
                            "items.dateThrough",
                            short_date(editor.days.through),
                            Action::Through,
                            !editor.picking_from,
                        )),
                )
                .push(widget::calendar(
                    &editor.calendar,
                    |day| Message::DateFilter(Action::Select(day)),
                    || Message::DateFilter(Action::PreviousMonth),
                    || Message::DateFilter(Action::NextMonth),
                    Weekday::Monday,
                ))
                .push(
                    widget::button::suggested(t("items.applyDates")).on_press_maybe(
                        (editor.days.from <= editor.days.through).then_some(msg(Action::Apply)),
                    ),
                );
        }
        column.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusive_dates_follow_local_midnights_across_clock_changes() {
        let zone = TimeZone::get("America/New_York").unwrap();
        for (date, hours) in [("2026-03-08", 23), ("2026-11-01", 25)] {
            let day = date.parse::<Date>().unwrap();
            let range = Days {
                from: day,
                through: day,
            }
            .range(zone.clone())
            .unwrap()
            .unwrap();
            assert_eq!((range.end() - range.start()).num_hours(), hours);
        }
    }
}
