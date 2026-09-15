//! Synthetic MFA fixtures, not a replay of the certificate-authentication HAR.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

fn proofs(methods: &[(&str, bool)]) -> Vec<ArrUserProofs> {
    methods
        .iter()
        .map(|(id, is_default)| ArrUserProofs {
            auth_method_id: (*id).into(),
            is_default: *is_default,
            display: "synthetic display".into(),
        })
        .collect()
}

pub(crate) fn flow(methods: &[(&str, bool)], selected: Option<&str>) -> MFAAuthContinue {
    let proofs = proofs(methods);
    MFAAuthContinue {
        mfa_methods: proofs.iter().map(|p| p.auth_method_id.clone()).collect(),
        mfa_method_details: proofs.iter().map(MfaMethodInfo::from).collect(),
        selected_mfa_method_id: selected.map(str::to_string),
        ..Default::default()
    }
}

#[test]
fn native_selection_preserves_precedence_and_skips_unsupported_proofs() {
    type Case<'a> = (
        &'a [(&'a str, bool)],
        Option<&'a str>,
        bool,
        Option<&'a str>,
    );
    let cases: &[Case<'_>] = &[
        (
            &[("Certificate", true), ("PhoneAppOTP", false)],
            None,
            false,
            Some("PhoneAppOTP"),
        ),
        (
            &[("Certificate", true), ("PhoneAppOTP", false)],
            Some("PhoneAppOTP"),
            false,
            Some("PhoneAppOTP"),
        ),
        (
            &[("Unknown", true), ("PhoneAppOTP", false)],
            None,
            false,
            Some("PhoneAppOTP"),
        ),
        (
            &[("Certificate", false), ("PhoneAppOTP", false)],
            None,
            false,
            Some("PhoneAppOTP"),
        ),
        (
            &[("PhoneAppOTP", false), ("OneWaySMS", true)],
            None,
            false,
            Some("OneWaySMS"),
        ),
        (
            &[("OneWaySMS", true), ("PhoneAppOTP", false)],
            Some("PhoneAppOTP"),
            false,
            Some("PhoneAppOTP"),
        ),
        (
            &[("Certificate", true), ("Unknown", false)],
            None,
            false,
            None,
        ),
        (&[], None, false, None),
        (
            &[
                ("FidoKey", true),
                ("PhoneAppOTP", false),
                ("PhoneAppNotification", false),
            ],
            None,
            true,
            Some("PhoneAppNotification"),
        ),
        (
            &[("FidoKey", true), ("PhoneAppOTP", false)],
            None,
            true,
            Some("PhoneAppOTP"),
        ),
        (
            &[("FidoKey", true), ("PhoneAppOTP", false)],
            None,
            false,
            Some("FidoKey"),
        ),
        (
            &[
                ("Certificate", true),
                ("OneWaySMS", true),
                ("PhoneAppOTP", true),
            ],
            None,
            false,
            Some("OneWaySMS"),
        ),
        (
            &[("PhoneAppOTP", true), ("PhoneAppNotification", false)],
            None,
            true,
            Some("PhoneAppOTP"),
        ),
        (&[("FidoKey", true)], None, true, None),
    ];
    for &(methods, requested, skip_fido, expected) in cases {
        let proofs = proofs(methods);
        let selected = select_native_mfa_method(&proofs, requested, skip_fido).unwrap();
        assert_eq!(
            selected.map(|p| p.auth_method_id.as_str()),
            expected,
            "{methods:?}, preference={requested:?}, skip_fido={skip_fido}"
        );
    }
}

#[test]
fn every_implemented_native_handler_is_selectable() {
    for id in [
        "PhoneAppOTP",
        "OneWaySMS",
        "ConsolidatedTelephony",
        "PhoneAppNotification",
        "CompanionAppsNotification",
        "TwoWayVoiceMobile",
        "TwoWayVoiceAlternateMobile",
        "TwoWayVoiceOffice",
        "AccessPass",
        "FidoKey",
    ] {
        let proofs = proofs(&[(id, true)]);
        assert_eq!(
            select_native_mfa_method(&proofs, None, false)
                .unwrap()
                .unwrap()
                .auth_method_id,
            id
        );
    }
}

#[test]
fn unavailable_preferences_keep_the_consumer_error_contract() {
    let proofs = proofs(&[
        ("Certificate", true),
        ("PhoneAppOTP", false),
        ("FidoKey", false),
    ]);
    for requested in ["Absent", "Certificate", "FidoKey"] {
        let result = select_native_mfa_method(&proofs, Some(requested), true);
        assert!(
            matches!(result, Err(MsalError::GeneralFailure(ref msg)) if msg == &format!(
                "Requested MFA method '{}' not available. Available methods: Certificate, PhoneAppOTP, FidoKey", requested
            ))
        );
    }
}

#[test]
fn selected_accessors_preserve_account_defaults_and_serialization() {
    for (default, selected) in [
        ("Certificate", "PhoneAppOTP"),
        ("Unknown", "PhoneAppOTP"),
        ("PhoneAppNotification", "PhoneAppOTP"),
        ("PhoneAppOTP", "PhoneAppNotification"),
        ("PhoneAppOTP", "OneWaySMS"),
        ("PhoneAppOTP", "FidoKey"),
        ("PhoneAppOTP", "AccessPass"),
    ] {
        let original = flow(&[(default, true), (selected, false)], Some(selected));
        let serialized = serde_json::to_value(&original).unwrap();
        assert_eq!(serialized["selected_mfa_method_id"], selected);
        assert_eq!(serialized["mfa_methods"], json!([default, selected]));
        assert_eq!(
            serialized["mfa_method_details"][0],
            json!({
                "auth_method_id": default,
                "is_default": true,
                "display": "synthetic display"
            })
        );
        assert_eq!(
            serialized["mfa_method_details"][1],
            json!({
                "auth_method_id": selected,
                "is_default": false,
                "display": "synthetic display"
            })
        );
        let restored: MFAAuthContinue = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(restored.mfa_method(), selected);
        assert_eq!(
            restored
                .get_selected_mfa_method_details()
                .unwrap()
                .auth_method_id,
            selected
        );
        assert_eq!(
            restored
                .get_default_mfa_method_details()
                .unwrap()
                .auth_method_id,
            selected
        );
        assert_eq!(restored.selected_mfa_method_id.as_deref(), Some(selected));
        assert_eq!(serde_json::to_value(&restored).unwrap(), serialized);
        assert_eq!(restored.mfa_methods, [default, selected]);
        assert_eq!(restored.mfa_method_details[0].auth_method_id, default);
        assert_eq!(restored.mfa_method_details[0].display, "synthetic display");
        assert!(restored.mfa_method_details[0].is_default);
        assert_eq!(restored.mfa_method_details[1].display, "synthetic display");
        assert!(!restored.mfa_method_details[1].is_default);
    }
}

#[test]
fn active_method_resolution_always_uses_native_selection_policy() {
    let methods = [("Certificate", true), ("PhoneAppOTP", false)];
    let automatic = flow(&methods, None);
    assert_eq!(automatic.mfa_method(), "PhoneAppOTP");
    assert_eq!(
        automatic
            .get_selected_mfa_method_details()
            .unwrap()
            .auth_method_id,
        "PhoneAppOTP"
    );
    assert_eq!(
        automatic
            .get_default_mfa_method_details()
            .unwrap()
            .auth_method_id,
        "PhoneAppOTP"
    );

    let no_marked_default = flow(&[("OneWaySMS", false), ("PhoneAppOTP", false)], None);
    assert_eq!(
        no_marked_default
            .get_default_mfa_method_details()
            .unwrap()
            .auth_method_id,
        "OneWaySMS"
    );

    let mut skip_fido = flow(&[("FidoKey", true), ("PhoneAppOTP", false)], None);
    skip_fido.skip_fido_for_mfa = true;
    assert_eq!(
        skip_fido
            .get_default_mfa_method_details()
            .unwrap()
            .auth_method_id,
        "PhoneAppOTP"
    );

    let invalid = flow(&methods, Some("Missing"));
    assert!(invalid.get_selected_mfa_method_details().is_none());
    assert!(invalid.get_default_mfa_method_details().is_none());
    assert_eq!(invalid.mfa_method(), "");

    let unsupported = flow(&methods, Some("Certificate"));
    assert!(unsupported.get_selected_mfa_method_details().is_none());
    assert!(unsupported.get_default_mfa_method_details().is_none());
    assert_eq!(unsupported.mfa_method(), "");

    let mut ineligible_fido = flow(
        &[("FidoKey", true), ("PhoneAppOTP", false)],
        Some("FidoKey"),
    );
    ineligible_fido.skip_fido_for_mfa = true;
    assert!(ineligible_fido.get_selected_mfa_method_details().is_none());
    assert_eq!(ineligible_fido.mfa_method(), "");

    let mut missing_details = flow(&[("Certificate", true)], Some("PhoneAppOTP"));
    missing_details.mfa_methods.push("PhoneAppOTP".into());
    assert!(missing_details.get_selected_mfa_method_details().is_none());
    assert!(missing_details.get_default_mfa_method_details().is_none());

    let empty = MFAAuthContinue::default();
    assert!(empty.get_selected_mfa_method_details().is_none());
    assert!(empty.get_default_mfa_method_details().is_none());
    assert!(flow(&[("Certificate", true)], None)
        .get_selected_mfa_method_details()
        .is_none());
    assert_eq!(
        flow(&[("OneWaySMS", false)], None).mfa_method(),
        "OneWaySMS"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumerDispatch {
    Fido,
    Input,
    Poll,
}

fn classify_consumer_method(method_id: Option<&str>) -> ConsumerDispatch {
    match method_id {
        Some("FidoKey") => ConsumerDispatch::Fido,
        Some("AccessPass" | "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony") => {
            ConsumerDispatch::Input
        }
        _ => ConsumerDispatch::Poll,
    }
}

// Mirrors the unchanged details-based consumer dispatch at these pinned commits:
// main 7e4f1ab3627a, stable-4.x a4ab65ada231, and stable-3.x 7d1ea961cae1.
fn details_consumer_dispatch(flow: &MFAAuthContinue) -> ConsumerDispatch {
    let method = flow.get_default_mfa_method_details();
    classify_consumer_method(method.as_ref().map(|info| info.auth_method_id.as_str()))
}

// Mirrors the unchanged stable-2.x consumer dispatch at 2fd621a427f8.
fn string_consumer_dispatch(flow: &MFAAuthContinue) -> ConsumerDispatch {
    classify_consumer_method(Some(flow.mfa_method().as_str()))
}

// Mirrors main/4.x's mfa_flow_uses_push_hint predicate at the commits above.
fn details_consumer_uses_push_hint(flow: &MFAAuthContinue) -> bool {
    flow.get_default_mfa_method_details().is_some_and(|method| {
        matches!(
            method.auth_method_id.as_str(),
            "PhoneAppNotification" | "CompanionAppsNotification"
        )
    })
}

#[test]
fn unchanged_consumer_fixtures_dispatch_the_active_selection() {
    for (selected, expected, push_hint) in [
        ("PhoneAppOTP", ConsumerDispatch::Input, false),
        ("OneWaySMS", ConsumerDispatch::Input, false),
        ("FidoKey", ConsumerDispatch::Fido, false),
        ("AccessPass", ConsumerDispatch::Input, false),
        ("PhoneAppNotification", ConsumerDispatch::Poll, true),
    ] {
        let selected_flow = flow(&[("Certificate", true), (selected, false)], Some(selected));
        assert_eq!(details_consumer_dispatch(&selected_flow), expected);
        assert_eq!(string_consumer_dispatch(&selected_flow), expected);
        assert_eq!(details_consumer_uses_push_hint(&selected_flow), push_hint);
    }

    let empty = MFAAuthContinue::default();
    assert_eq!(details_consumer_dispatch(&empty), ConsumerDispatch::Poll);
    assert_eq!(string_consumer_dispatch(&empty), ConsumerDispatch::Poll);
}

#[derive(Clone, Debug)]
struct Request {
    target: String,
    body: String,
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    task: JoinHandle<()>,
}

impl Server {
    // Responses contain an optional $BASE placeholder for this server's ephemeral URL.
    async fn start(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            let mut responses = responses.into_iter();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buf = [0; 4096];
                    let count = stream.read(&mut buf).await.unwrap();
                    assert_ne!(count, 0, "incomplete HTTP headers");
                    bytes.extend_from_slice(&buf[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let mut buf = [0; 4096];
                    let count = stream.read(&mut buf).await.unwrap();
                    assert_ne!(count, 0, "incomplete HTTP body");
                    bytes.extend_from_slice(&buf[..count]);
                }
                captured.lock().unwrap().push(Request {
                    target: headers
                        .lines()
                        .next()
                        .unwrap()
                        .trim_end_matches(" HTTP/1.1")
                        .to_string(),
                    body: String::from_utf8(bytes[header_end..header_end + length].to_vec())
                        .unwrap(),
                });
                let response = responses
                    .next()
                    .unwrap_or_else(|| "500 Unexpected request\r\n\r\n".into())
                    .replace("$BASE", &base);
                let (status_headers, body) = response.split_once("\r\n\r\n").unwrap();
                let wire = format!("HTTP/1.1 {status_headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(wire.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn client(&self) -> PublicClientApplication {
        let mut app = PublicClientApplication::new(
            "synthetic-client",
            Some(&self.url),
            #[cfg(feature = "set_timeout")]
            Duration::from_secs(3),
            #[cfg(feature = "ipvers")]
            &[],
        )
        .unwrap();
        // Isolate fixtures from developer proxy settings without changing production behavior.
        app.app.client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .cookie_provider(app.app.jar.clone())
            .build()
            .unwrap();
        app
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn json_response(body: &Value) -> String {
    format!("200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
}

fn config(methods: &[(&str, bool)]) -> Value {
    json!({
        "sessionId": "synthetic-session", "sCtx": "login-ctx", "sFT": "login-token",
        "canary": "synthetic-canary", "urlPost": "$BASE/process",
        "urlBeginAuth": "$BASE/begin", "urlEndAuth": "$BASE/end",
        "arrUserProofs": methods.iter().map(|(id, default)| json!({
            "authMethodId": id, "isDefault": default, "display": "synthetic display"
        })).collect::<Vec<_>>()
    })
}

fn config_response(methods: &[(&str, bool)]) -> String {
    format!(
        "200 OK\r\nContent-Type: text/html\r\n\r\n<script>$Config={};\n//]]></script>",
        config(methods)
    )
}

fn auth_init(server: &Server) -> AuthInit {
    let mut config = config(&[]);
    config["urlPost"] = json!(format!("{}/login", server.url));
    AuthInit {
        auth_config: serde_json::from_value(config).unwrap(),
        cred_type: serde_json::from_value(json!({
            "Credentials": { "PrefCredential": 1, "HasPassword": true },
            "ThrottleStatus": 0, "IfExistsResult": 0
        }))
        .unwrap(),
    }
}

async fn initiate(
    app: &PublicClientApplication,
    init: AuthInit,
    options: &[AuthOption],
    requested: Option<&str>,
) -> Result<MFAAuthContinue, MsalError> {
    #[cfg(not(feature = "mfa_method_selection"))]
    let _ = requested;
    app.initiate_acquire_token_by_mfa_flow(
        "user@example.test",
        Some("synthetic-password"),
        vec![],
        None,
        options,
        Some(init),
        #[cfg(feature = "mfa_method_selection")]
        requested,
    )
    .await
}

fn auth_response(success: bool) -> Value {
    json!({"Success": success, "Retry": false, "Ctx": "begin-ctx", "FlowToken": "begin-token", "Entropy": 0})
}

fn device_response() -> Value {
    json!({"device_code": "synthetic-device", "user_code": "TEST-CODE", "verification_uri": "https://example.test/device", "expires_in": 600, "interval": 5})
}

#[tokio::test]
async fn unsupported_default_uses_otp_post_and_preserves_continuation_tokens() {
    let cases = [
        ("Certificate", None, false),
        // A method-bearing continuation without a stored selection must use
        // the same corrected selection policy when it is consumed.
        ("Unknown", None, true),
        #[cfg(feature = "mfa_method_selection")]
        ("Certificate", Some("PhoneAppOTP"), false),
        #[cfg(feature = "mfa_method_selection")]
        ("PhoneAppNotification", Some("PhoneAppOTP"), false),
    ];
    for (default, requested, clear_selection) in cases {
        let mut end = auth_response(true);
        end["Ctx"] = json!("end-ctx");
        end["FlowToken"] = json!("end-token");
        let server = Server::start(vec![
            config_response(&[(default, true), ("PhoneAppOTP", false)]),
            json_response(&auth_response(true)), json_response(&end),
            "302 Found\r\nLocation: https://example.test/callback?code=synthetic-code\r\n\r\n".into(),
            json_response(&json!({"token_type": "Bearer", "expires_in": 3600, "ext_expires_in": 3600, "access_token": "synthetic-access", "refresh_token": "synthetic-refresh"})),
        ]).await;
        let app = server.client();
        let mut flow = initiate(&app, auth_init(&server), &[], requested)
            .await
            .unwrap();
        if clear_selection {
            flow.selected_mfa_method_id = None;
        }
        assert_eq!(flow.mfa_method(), "PhoneAppOTP");
        assert_eq!(
            flow.get_default_mfa_method_details()
                .unwrap()
                .auth_method_id,
            "PhoneAppOTP"
        );
        assert_eq!(details_consumer_dispatch(&flow), ConsumerDispatch::Input);
        assert_eq!(string_consumer_dispatch(&flow), ConsumerDispatch::Input);
        assert!(!details_consumer_uses_push_hint(&flow));
        assert_eq!(flow.mfa_method_details[0].auth_method_id, default);
        assert!(flow.mfa_method_details[0].is_default);
        assert!(!flow.mfa_method_details[1].is_default);
        assert_eq!(
            (flow.ctx.as_str(), flow.flow_token.as_str()),
            ("begin-ctx", "begin-token")
        );
        // Initiation finishes after BeginAuth, with no EndAuth poll while awaiting input.
        assert_eq!(
            server
                .requests()
                .iter()
                .map(|r| r.target.as_str())
                .collect::<Vec<_>>(),
            ["POST /login", "POST /begin"]
        );
        let token = app
            .acquire_token_by_mfa_flow("user@example.test", Some(" 123456 "), None, &mut flow)
            .await
            .unwrap();
        assert_eq!(token.access_token.as_deref(), Some("synthetic-access"));
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .map(|r| r.target.as_str())
                .collect::<Vec<_>>(),
            [
                "POST /login",
                "POST /begin",
                "POST /end",
                "POST /process",
                "POST /oauth2/token"
            ]
        );
        let begin: Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(
            begin,
            json!({"AuthMethodId": "PhoneAppOTP", "ctx": "login-ctx", "flowToken": "login-token", "Method": "BeginAuth"})
        );
        let end: Value = serde_json::from_str(&requests[2].body).unwrap();
        assert_eq!(
            end,
            json!({"AdditionalAuthData": "123456", "AuthMethodId": "PhoneAppOTP", "SessionId": "synthetic-session", "FlowToken": "begin-token", "Ctx": "begin-ctx", "Method": "EndAuth"})
        );
        let process: HashMap<String, String> =
            serde_urlencoded::from_str(&requests[3].body).unwrap();
        assert_eq!(process["request"], "end-ctx");
        assert_eq!(process["flowToken"], "end-token");
        assert_eq!(process["mfaAuthMethod"], "PhoneAppOTP");
        assert_eq!(
            (flow.ctx.as_str(), flow.flow_token.as_str()),
            ("end-ctx", "end-token")
        );
    }
}

#[cfg(feature = "mfa_method_selection")]
#[tokio::test]
async fn explicit_notification_uses_poll_dispatch_and_selected_method_id() {
    let server = Server::start(vec![
        config_response(&[("PhoneAppOTP", true), ("PhoneAppNotification", false)]),
        json_response(&auth_response(true)),
        json_response(&auth_response(false)),
    ])
    .await;
    let app = server.client();
    let mut flow = initiate(&app, auth_init(&server), &[], Some("PhoneAppNotification"))
        .await
        .unwrap();

    assert_eq!(details_consumer_dispatch(&flow), ConsumerDispatch::Poll);
    assert_eq!(string_consumer_dispatch(&flow), ConsumerDispatch::Poll);
    assert!(details_consumer_uses_push_hint(&flow));
    assert_eq!(
        flow.get_default_mfa_method_details()
            .unwrap()
            .auth_method_id,
        "PhoneAppNotification"
    );
    assert!(flow.mfa_method_details[0].is_default);
    assert!(!flow.mfa_method_details[1].is_default);
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        ["POST /login", "POST /begin"]
    );

    let result = app
        .acquire_token_by_mfa_flow("user@example.test", None, Some(1), &mut flow)
        .await;
    assert!(matches!(result, Err(MsalError::AuthorizationDenied)));
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        [
            "POST /login",
            "POST /begin",
            "GET /end?authMethodId=PhoneAppNotification&pollCount=1"
        ]
    );
}

#[tokio::test]
async fn unsupported_only_proofs_follow_device_fallback_policy() {
    for methods in [vec![("Certificate", true), ("Unknown", false)], vec![]] {
        for disabled in [false, true] {
            let server = Server::start(vec![
                config_response(&methods),
                json_response(&device_response()),
            ])
            .await;
            let options = if disabled {
                vec![AuthOption::NoDAGFallback]
            } else {
                vec![]
            };
            let result = initiate(&server.client(), auth_init(&server), &options, None).await;
            let requests = server.requests();
            if disabled {
                assert!(matches!(result, Err(MsalError::MFADAGFallbackDisabled)));
                assert_eq!(
                    requests
                        .iter()
                        .map(|r| r.target.as_str())
                        .collect::<Vec<_>>(),
                    ["POST /login"]
                );
            } else {
                assert!(result.unwrap().dag.is_some());
                assert_eq!(
                    requests
                        .iter()
                        .map(|r| r.target.as_str())
                        .collect::<Vec<_>>(),
                    ["POST /login", "POST /oauth2/v2.0/devicecode"]
                );
            }
        }
    }
}

#[cfg(feature = "mfa_method_selection")]
#[tokio::test]
async fn unsupported_explicit_preference_never_starts_native_or_device_auth() {
    for requested in ["Certificate", "Unknown"] {
        let server = Server::start(vec![config_response(&[
            (requested, true),
            ("PhoneAppOTP", false),
        ])])
        .await;
        let result = initiate(&server.client(), auth_init(&server), &[], Some(requested)).await;
        assert!(
            matches!(result, Err(MsalError::GeneralFailure(ref msg)) if msg.starts_with(&format!("Requested MFA method '{}' not available. Available methods:", requested)))
        );
        assert_eq!(
            server
                .requests()
                .iter()
                .map(|r| r.target.as_str())
                .collect::<Vec<_>>(),
            ["POST /login"]
        );
    }
}

#[tokio::test]
async fn begin_auth_policy_denial_does_not_retry_or_fallback() {
    let mut denial = auth_response(false);
    denial["ErrCode"] = json!(50087);
    let server = Server::start(vec![
        config_response(&[
            ("Certificate", true),
            ("PhoneAppOTP", false),
            ("OneWaySMS", false),
        ]),
        json_response(&denial),
    ])
    .await;
    let result = initiate(&server.client(), auth_init(&server), &[], None).await;
    assert!(matches!(result, Err(MsalError::AADSTSError(ref err)) if err.code == 50087));
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|r| r.target.as_str())
            .collect::<Vec<_>>(),
        ["POST /login", "POST /begin"]
    );
}

#[tokio::test]
async fn terminal_push_denial_does_not_retry_or_fallback() {
    let server = Server::start(vec![
        config_response(&[("PhoneAppNotification", true), ("PhoneAppOTP", false)]),
        json_response(&auth_response(true)),
        json_response(&auth_response(false)),
    ])
    .await;
    let app = server.client();
    let mut flow = initiate(&app, auth_init(&server), &[], None).await.unwrap();
    let result = app
        .acquire_token_by_mfa_flow("user@example.test", None, Some(1), &mut flow)
        .await;
    assert!(matches!(result, Err(MsalError::AuthorizationDenied)));
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|r| r.target.as_str())
            .collect::<Vec<_>>(),
        [
            "POST /login",
            "POST /begin",
            "GET /end?authMethodId=PhoneAppNotification&pollCount=1"
        ]
    );
}

#[tokio::test]
async fn failed_remote_ngc_does_not_send_a_duplicate_push() {
    let server = Server::start(vec![
        json_response(&json!({"error": {"message": "synthetic failure"}})),
        config_response(&[("Certificate", true), ("PhoneAppNotification", false)]),
        json_response(&device_response()),
    ])
    .await;
    let mut init = auth_init(&server);
    init.cred_type.credentials.remote_ngc_params = Some(RemoteNgcParams {
        session_identifier: "synthetic-ngc".into(),
        entropy: 0,
    });
    let flow = initiate(&server.client(), init, &[], None).await.unwrap();
    assert!(flow.dag.is_some());
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|r| r.target.as_str())
            .collect::<Vec<_>>(),
        [
            "POST /GetOneTimeCode",
            "POST /login",
            "POST /oauth2/v2.0/devicecode"
        ]
    );
}

#[tokio::test]
async fn invalid_stored_selection_rejects_completion_without_requests() {
    let server = Server::start(vec![]).await;
    let app = server.client();
    let mut missing_details = flow(&[("Certificate", true)], Some("PhoneAppOTP"));
    missing_details.mfa_methods.push("PhoneAppOTP".into());
    let mut ineligible_fido = flow(
        &[("FidoKey", true), ("PhoneAppOTP", false)],
        Some("FidoKey"),
    );
    ineligible_fido.skip_fido_for_mfa = true;
    for (mut flow, expected) in [
        (
            flow(&[("Certificate", true)], Some("PhoneAppOTP")),
            "Stored MFA method 'PhoneAppOTP' is not available. Available methods: \"Certificate\"",
        ),
        (
            missing_details,
            "Unable to determine MFA method details - selected method was: PhoneAppOTP",
        ),
        (
            flow(
                &[("Certificate", true), ("PhoneAppOTP", false)],
                Some("Certificate"),
            ),
            "Unable to determine MFA method details - selected method was: Certificate",
        ),
        (
            ineligible_fido,
            "Unable to determine MFA method details - selected method was: FidoKey",
        ),
    ] {
        let result = app
            .acquire_token_by_mfa_flow("user@example.test", Some("123456"), None, &mut flow)
            .await;
        assert!(matches!(result, Err(MsalError::GeneralFailure(ref msg)) if msg == expected));
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn empty_device_and_direct_code_flows_bypass_proof_lookup() {
    for device in [false, true] {
        let server = Server::start(vec!["400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"access_denied\",\"error_description\":\"synthetic denial\",\"error_codes\":[50087]}".into()]).await;
        let mut flow = if device {
            let dag: DeviceAuthorizationResponse =
                serde_json::from_value(device_response()).unwrap();
            dag.into()
        } else {
            MFAAuthContinue {
                auth_code: Some("synthetic-code".into()),
                ..Default::default()
            }
        };
        let result = server
            .client()
            .acquire_token_by_mfa_flow("user@example.test", None, Some(1), &mut flow)
            .await;
        assert!(
            matches!(result, Err(MsalError::AcquireTokenFailed(ref err)) if err.error == "access_denied")
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].target,
            if device {
                "POST /oauth2/v2.0/token"
            } else {
                "POST /oauth2/token"
            }
        );
    }
}

#[tokio::test]
async fn rejected_otp_submission_does_not_switch_methods_or_start_device_auth() {
    let server = Server::start(vec![
        config_response(&[
            ("Certificate", true),
            ("PhoneAppOTP", false),
            ("OneWaySMS", false),
        ]),
        json_response(&auth_response(true)),
        json_response(&auth_response(false)),
    ])
    .await;
    let app = server.client();
    let mut flow = initiate(&app, auth_init(&server), &[], None).await.unwrap();
    let result = app
        .acquire_token_by_mfa_flow("user@example.test", Some("123456"), None, &mut flow)
        .await;
    assert!(matches!(result, Err(MsalError::GeneralFailure(ref msg)) if msg == "EndAuth failed"));
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|r| r.target.as_str())
            .collect::<Vec<_>>(),
        ["POST /login", "POST /begin", "POST /end"]
    );
}
