mod support;
use std::sync::mpsc;
use std::time::Duration;
use support::*;

#[test]
fn native_lock_waits_for_secret_delivery_and_no_later_fill_reaches_the_sink() {
    let fixture = Fixture::new();
    let item = fixture.login("Example", "https://example.com");
    let vault = fixture.vault.clone();
    let (entered, ready) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        vault.browser_fill(context("https://example.com"), item, &mut |_| {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(())
        })
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let vault = fixture.vault.clone();
    let (locked, done) = mpsc::channel();
    let lock = std::thread::spawn(move || {
        vault.lock().unwrap();
        locked.send(()).unwrap();
    });
    assert!(done.recv_timeout(Duration::from_millis(50)).is_err());
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    done.recv_timeout(Duration::from_secs(2)).unwrap();
    lock.join().unwrap();
    let mut called = false;
    assert!(fixture
        .vault
        .browser_fill(
            context("https://example.com"),
            "invalid".into(),
            &mut |_| {
                called = true;
                Ok(())
            }
        )
        .is_err());
    assert!(!called);
}
