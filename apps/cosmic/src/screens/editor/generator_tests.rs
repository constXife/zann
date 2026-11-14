use super::*;
use zann_ui_core::generator::MAX_PASSWORD_LENGTH;

fn editor() -> State {
    let mut editor = State::create("login").unwrap();
    editor.update(Message::Path("mail".into()));
    editor
}

#[test]
fn generated_password_enters_the_existing_masked_draft_and_save_payload() {
    let mut editor = editor();
    editor.update(Message::ToggleReveal(1));
    editor.update(Message::OpenGenerator(1));
    editor.update(Message::Generator(generator::Message::Length(
        MAX_PASSWORD_LENGTH,
    )));
    editor.update(Message::Generator(generator::Message::Generate));
    assert_eq!(
        editor.draft.fields[1].value.value.len(),
        MAX_PASSWORD_LENGTH as usize
    );
    assert!(!editor.revealed[1]);
    assert!(editor.draft.fields[1].masked());
    assert!(editor.generator_field.is_none());
    let Outcome::Submit(SaveRequest::Create(request)) = editor.update(Message::Submit) else {
        panic!("valid generated draft")
    };
    let payload: Value = serde_json::from_str(&request.payload_json).unwrap();
    assert_eq!(
        payload["fields"]["password"]["value"]
            .as_str()
            .unwrap()
            .len(),
        MAX_PASSWORD_LENGTH as usize
    );
    assert_eq!(payload["fields"]["password"]["kind"], "password");
}

#[test]
fn passphrase_generation_uses_the_shared_default_and_selected_word_count() {
    let mut editor = editor();
    editor.update(Message::OpenGenerator(1));
    editor.update(Message::Generator(generator::Message::Mode(true)));
    editor.update(Message::Generator(generator::Message::Words(8)));
    editor.update(Message::Generator(generator::Message::Generate));
    let value = &editor.draft.fields[1].value.value;
    assert_eq!(value.split(' ').count(), 8);
    assert!(!editor.revealed[1]);
}

#[test]
fn invalid_policy_preserves_the_previous_value_and_reports_an_error() {
    let mut editor = editor();
    editor.update(Message::FieldValue(1, "existing".into()));
    editor.update(Message::OpenGenerator(1));
    for message in [
        generator::Message::Lowercase(false),
        generator::Message::Uppercase(false),
        generator::Message::Digits(false),
        generator::Message::Symbols(false),
    ] {
        editor.update(Message::Generator(message));
    }
    editor.update(Message::Generator(generator::Message::Generate));
    assert_eq!(editor.draft.fields[1].value.value, "existing");
    assert!(editor.error.is_some());
    assert_eq!(editor.generator_field, Some(1));
}

#[test]
fn field_changes_and_focus_loss_close_the_generator_without_mutating_other_fields() {
    let mut editor = editor();
    editor.update(Message::OpenGenerator(0)); // username is not a password
    assert!(editor.generator_field.is_none());
    editor.update(Message::OpenGenerator(1));
    editor.update(Message::RemoveField(0));
    editor.update(Message::Generator(generator::Message::Generate));
    assert!(editor.draft.fields[0].value.value.is_empty());
    editor.update(Message::OpenGenerator(0));
    editor.hide_revealed();
    assert!(editor.generator_field.is_none());
    editor.update(Message::OpenGenerator(0));
    editor.update(Message::FieldKind(0, FieldKind::Text));
    editor.update(Message::Generator(generator::Message::Generate));
    assert!(editor.draft.fields[0].value.value.is_empty());
}
