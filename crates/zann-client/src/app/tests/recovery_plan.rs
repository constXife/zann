use super::*;

#[tokio::test]
async fn prepared_forget_rejects_config_drift_and_preserves_other_connections() {
    let dir = tempfile::tempdir().expect("temp dir");
    let app = trusting_client(&dir);
    let mut server = mockito::Server::new_async().await;
    first_connect(&app, &mut server).await;
    let snapshot = app.repository.snapshot().expect("snapshot");
    let storage = snapshot
        .config()
        .connections
        .values()
        .next()
        .expect("connection")
        .profile_storage_id("default")
        .expect("reserved replica")
        .to_owned();
    let stale = app.prepare_account_removal(&storage).expect("plan");
    assert!(stale.is_configured());
    let mut second = mockito::Server::new_async().await;
    first_connect(&app, &mut second).await;
    assert!(app.commit_account_removal(stale).is_err());
    assert!(app.syncs_storage(&storage).expect("original retained"));
    let current = app.prepare_account_removal(&storage).expect("fresh plan");
    app.commit_account_removal(current)
        .expect("forget selected");
    assert!(!app.syncs_storage(&storage).expect("selected absent"));
    let snapshot = app.repository.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.config().connections.len(),
        2,
        "endpoint trust is retained"
    );
    assert!(snapshot
        .config()
        .replica_profile(&storage)
        .expect("lookup")
        .is_none());
}

#[tokio::test]
async fn absent_storage_plan_is_bound_to_exact_config_revision() {
    let dir = tempfile::tempdir().expect("temp dir");
    let app = trusting_client(&dir);
    let mut server = mockito::Server::new_async().await;
    let plan = app
        .prepare_account_removal("disconnected-cache")
        .expect("plan");
    assert!(!plan.is_configured());
    first_connect(&app, &mut server).await;
    assert!(app.commit_account_removal(plan).is_err());
    let plan = app
        .prepare_account_removal("disconnected-cache")
        .expect("new plan");
    app.commit_account_removal(plan).expect("nothing to forget");
    assert_eq!(
        app.repository
            .snapshot()
            .expect("snapshot")
            .config()
            .connections
            .len(),
        1
    );
}
