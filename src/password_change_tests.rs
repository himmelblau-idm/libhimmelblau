//! Changing a password Entra says must be changed, against the scripted test server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::test_server::{json_response, Server};
use super::*;

// The page Entra shows when the password must be changed, reached after the
// password (and after MFA, if required).
fn change_page(base: &str) -> String {
    let config = json!({
        "sessionId": "synthetic-session", "sCtx": "change-ctx", "sFT": "change-token",
        "canary": "synthetic-canary", "pgid": "ConvergedChangePassword",
        "urlPost": format!("{base}/post"),
        "urlAsyncSsprBegin": format!("{base}/sspr/begin"),
        "urlAsyncSsprPoll": format!("{base}/sspr/poll")
    });
    format!("<script>$Config={config};\n//]]></script>")
}

fn sspr_done() -> String {
    json_response(&json!({
        "IsJobPending": false, "Ctx": "sspr-ctx", "FlowToken": "sspr-token",
        "CoupledDataCenter": "synthetic-dc", "CoupledScaleUnit": "synthetic-su"
    }))
}

#[tokio::test]
async fn the_change_page_the_sign_in_reached_is_used() {
    let server = Server::start(vec![sspr_done(), "200 OK\r\n\r\n".to_string()]).await;
    let app = server.client();
    assert!(matches!(
        app.parse_auth_config(&change_page(&server.url), false, false),
        Err(MsalError::ChangePassword)
    ));

    app.handle_password_change("user@example.test", "old-password", "new-password")
        .await
        .unwrap();

    // Straight to the change: no second sign-in, which after MFA would end at
    // MFA, not at this page.
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0].target, "POST /sspr/begin");
    let begin: Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(begin["Ctx"], "change-ctx");
    assert_eq!(begin["FlowToken"], "change-token");
    assert_eq!(begin["OldPassword"], "old-password");
    assert_eq!(begin["NewPassword"], "new-password");
    assert_eq!(requests[1].target, "POST /post");
}

#[tokio::test]
async fn the_change_page_is_used_once() {
    let server = Server::start(vec![sspr_done(), "200 OK\r\n\r\n".to_string()]).await;
    let app = server.client();
    let _ = app.parse_auth_config(&change_page(&server.url), false, false);
    app.handle_password_change("user@example.test", "old-password", "new-password")
        .await
        .unwrap();

    // Again without a new change page: a fresh sign-in, as before this page was kept.
    assert!(app
        .handle_password_change("user@example.test", "old-password", "new-password")
        .await
        .is_err());
    let requests = server.requests();
    assert_eq!(requests.len(), 3, "{requests:?}");
    assert!(
        requests[2].target.starts_with("GET /oauth2/authorize"),
        "{}",
        requests[2].target
    );
}
