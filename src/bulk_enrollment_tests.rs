//! Synthetic fixtures derived from the AADInternals wire contract, not live
//! tenant captures. No credentials or tenant mutations are needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::auth::test_server::{isolated_client, json_response, Request, Server};
use base64::engine::general_purpose::STANDARD;
use kanidm_hsm_crypto::{provider::SoftTpm, AuthValue};
use openssl::{
    bn::BigNum,
    x509::{X509Builder, X509NameBuilder, X509Req},
};

fn tenant() -> Uuid {
    Uuid::parse_str("6973bb37-65f8-440e-b39e-dd57da64f6cf").unwrap()
}

fn request() -> BulkEnrollmentRequest {
    BulkEnrollmentRequest::new(
        tenant(),
        "Linux installation",
        Utc::now().date_naive() + chrono::Duration::days(30),
    )
    .unwrap()
}

fn jwt(claims: &Value) -> String {
    format!(
        "synthetic.{}.signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    )
}

fn admin_token() -> String {
    jwt(&json!({"tid": tenant(), "aud": BULK_RESOURCE}))
}

fn package(request: &BulkEnrollmentRequest) -> BulkEnrollmentPackage {
    BulkEnrollmentPackage::import(request.metadata.clone(), "synthetic-bprt").unwrap()
}

fn completed(request: &BulkEnrollmentRequest) -> Value {
    json!({
        "state": "CompleteSuccess",
        "flowToken": null,
        "resultData": json!({
            "refresh_token": "synthetic-bprt",
            "id_token": jwt(&json!({
                "tid": request.metadata.tenant_id,
                "upn": format!("package_{}@example.test", request.metadata.package_id),
            })),
            "expires_on": (Utc::now() + chrono::Duration::days(30)).timestamp().to_string(),
        }).to_string(),
    })
}

fn broker(server: &Server) -> BrokerClientApplication {
    let mut app = BrokerClientApplication::new(
        Some(&server.url),
        None,
        None,
        None,
        #[cfg(feature = "set_timeout")]
        Duration::from_secs(3),
        #[cfg(feature = "ipvers")]
        &[],
    )
    .unwrap();
    app.app.app.client = isolated_client(&app.app.app.jar);
    app.discovery_url = Some(server.url.clone());
    app
}

#[test]
fn validation_and_explicit_replacement() {
    let today = Utc::now().date_naive();
    for days in [-1, 0, 91, 180] {
        assert!(BulkEnrollmentRequest::new(
            tenant(),
            "test",
            today + chrono::Duration::days(days),
        )
        .is_err());
    }
    for days in [1, 90] {
        assert!(BulkEnrollmentRequest::new(
            tenant(),
            "test",
            today + chrono::Duration::days(days),
        )
        .is_ok());
    }
    for name in ["".to_string(), " ".to_string(), "a".repeat(257)] {
        assert!(BulkEnrollmentRequest::new(
            tenant(),
            &name,
            today + chrono::Duration::days(30),
        )
        .is_err());
    }
    assert!(BulkEnrollmentRequest::new(
        Uuid::nil(),
        "test",
        today + chrono::Duration::days(30),
    )
    .is_err());
    let first = request();
    let second = request();
    assert_ne!(first.metadata.package_id, second.metadata.package_id);
    let replaced = second
        .replace_existing_package(first.metadata.package_id)
        .unwrap();
    assert_eq!(first.metadata.package_id, replaced.metadata.package_id);
    assert!(request().replace_existing_package(Uuid::nil()).is_err());
}

#[test]
fn package_import_and_redaction() {
    let request = request();
    let package = package(&request);
    assert_eq!(package.refresh_token(), "synthetic-bprt");
    let debug = format!("{:?}", package);
    assert!(!debug.contains("synthetic-bprt"));
    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains(&request.metadata.package_id.to_string()));
    assert!(BulkEnrollmentPackage::import(request.metadata.clone(), "").is_err());
    let mut expired = request.metadata.clone();
    expired.expires = Utc::now().date_naive();
    assert!(BulkEnrollmentPackage::import(expired, "synthetic-bprt").is_err());
}

#[test]
fn result_validation_and_service_expiry() {
    let request = request();
    let complete = completed(&request);
    let response: BulkResponse = serde_json::from_value(complete.clone()).unwrap();
    assert_eq!(
        package_from_response(&request, &response)
            .unwrap()
            .metadata(),
        request.metadata(),
    );
    let mut details: Value =
        serde_json::from_str(complete["resultData"].as_str().unwrap()).unwrap();
    let earlier = Utc::now().date_naive() + chrono::Duration::days(5);
    details["expires_on"] =
        json!(earlier.and_hms_opt(23, 59, 59).unwrap().and_utc().timestamp());
    let response: BulkResponse = serde_json::from_value(json!({
        "state": "CompleteSuccess", "resultData": details.to_string(),
    }))
    .unwrap();
    assert_eq!(
        package_from_response(&request, &response)
            .unwrap()
            .metadata()
            .expires,
        earlier,
    );
    for claims in [
        json!({"tid": Uuid::nil(), "upn": format!("package_{}@example.test", request.metadata.package_id)}),
        json!({"tid": tenant(), "upn": "package_wrong@example.test"}),
    ] {
        details["id_token"] = json!(jwt(&claims));
        let response: BulkResponse = serde_json::from_value(json!({
            "state": "CompleteSuccess", "resultData": details.to_string(),
        }))
        .unwrap();
        assert!(package_from_response(&request, &response).is_err());
    }
}

#[tokio::test]
async fn begin_poll_wire_contract() {
    let request = request()
        .replace_existing_package(
            Uuid::parse_str("e661278e-d204-43bd-aad4-e62cf9d9cf52").unwrap(),
        )
        .unwrap();
    let server = Server::start(vec![
        json_response(&json!({"state": "Started", "flowToken": "secret+/&=?"})),
        json_response(&completed(&request)),
    ])
    .await;
    let app = server.client();
    let package = app
        .create_bulk_enrollment_token(&admin_token(), &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(package.metadata(), request.metadata());
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "POST /webapp/bulkaadjtoken/begin");
    assert_eq!(
        serde_json::from_str::<Value>(&requests[0].body).unwrap(),
        json!({
            "pid": request.metadata.package_id,
            "name": "Linux installation",
            "exp": request.metadata.expires.format("%m/%d/%Y").to_string(),
        }),
    );
    let poll = requests[1].target.strip_prefix("GET ").unwrap();
    let url = Url::parse(&format!("{}{}", server.url, poll)).unwrap();
    assert_eq!(url.path(), "/webapp/bulkaadjtoken/poll");
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![("flowToken".into(), "secret+/&=?".into())],
    );
    for request in requests {
        assert!(request
            .headers
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {}", admin_token()).to_ascii_lowercase()));
    }
}

#[tokio::test]
async fn pending_flow_is_bounded_and_retains_encoded_flow_token() {
    let request = request();
    let server = Server::start(vec![
        json_response(&json!({"state": "Started", "flowToken": "secret+/&=?"})),
        json_response(&json!({"state": "InProgress", "flowToken": null})),
        json_response(&completed(&request)),
    ])
    .await;
    server
        .client()
        .create_bulk_enrollment_token(&admin_token(), &request, Duration::from_secs(5))
        .await
        .unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].target, requests[2].target);
}

#[tokio::test]
async fn deadline_does_not_retry_begin() {
    let server = Server::start(vec![
        json_response(&json!({"state": "Started", "flowToken": "secret-flow"})),
        json_response(&json!({"state": "InProgress"})),
    ])
    .await;
    let error = server
        .client()
        .create_bulk_enrollment_token(
            &admin_token(),
            &request(),
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(!error.to_string().contains("secret-flow"));
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn server_errors_and_malformed_responses_are_terminal() {
    for response in [
        json_response(&json!({
            "state": "CompleteError",
            "resultData": json!({
                "error": "unauthorized_client",
                "error_description": "AADSTS90092: Missing SyncFabric service principal",
            }).to_string(),
        })),
        "403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"access_denied\",\"error_description\":\"Tenant policy\"}".into(),
    ] {
        let server = Server::start(vec![response]).await;
        let error = server
            .client()
            .create_bulk_enrollment_token(&admin_token(), &request(), Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(matches!(error, MsalError::AcquireTokenFailed(_)));
        assert_eq!(server.requests().len(), 1);
    }
    for body in [
        json!({"state": "CompleteSuccess", "resultData": "secret-malformed-json"}),
        json!({"state": "Started"}),
        json!({"state": "Unexpected", "flowToken": "secret-flow"}),
        json!({"state": "CompleteError", "resultData": "secret-malformed-json"}),
    ] {
        let server = Server::start(vec![json_response(&body)]).await;
        let error = server
            .client()
            .create_bulk_enrollment_token(&admin_token(), &request(), Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("secret-"));
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn mismatched_admin_token_is_rejected_before_creation() {
    let server = Server::start(vec![]).await;
    for claims in [
        json!({"tid": Uuid::nil(), "aud": BULK_RESOURCE}),
        json!({"tid": tenant(), "aud": "https://graph.microsoft.com"}),
    ] {
        assert!(server
            .client()
            .create_bulk_enrollment_token(&jwt(&claims), &request(), Duration::from_secs(3))
            .await
            .is_err());
    }
    assert!(server.requests().is_empty());
}

#[test]
fn unverified_clouds_and_insecure_authorities_are_rejected() {
    for authority in [
        "http://login.microsoftonline.com/common",
        "https://login.microsoftonline.us/common",
        "https://example.test/common",
        "https://user:password@login.microsoftonline.com/common",
        "https://login.microsoftonline.com:8443/common",
    ] {
        assert!(validate_authority(&Url::parse(authority).unwrap()).is_err());
    }
}

#[tokio::test]
async fn bprt_exchange_uses_aadj_csp_v1_and_explicit_tenant() {
    let server = Server::start(vec![json_response(&json!({
        "access_token": "synthetic-drs-access",
    }))])
    .await;
    let token = broker(&server)
        .bulk_enrollment_access_token(&package(&request()))
        .await
        .unwrap();
    assert_eq!(token.access_token, "synthetic-drs-access");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target,
        format!("POST /{}/oauth2/token", tenant()),
    );
    let params: HashMap<String, String> =
        serde_urlencoded::from_str(&requests[0].body).unwrap();
    assert_eq!(params.len(), 4);
    assert_eq!(params["client_id"], BULK_CLIENT_ID);
    assert_eq!(params["resource"], BULK_RESOURCE);
    assert_eq!(params["grant_type"], "refresh_token");
    assert_eq!(params["refresh_token"], "synthetic-bprt");
}

#[tokio::test]
async fn expiry_and_exchange_failures_do_not_mutate_broker() {
    let server = Server::start(vec![
        "400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"invalid_grant\",\"error_description\":\"Package revoked\"}".into(),
        json_response(&json!({"access_token": ""})),
        json_response(&json!({"other": "secret-unexpected-body"})),
    ])
    .await;
    let app = broker(&server);
    let mut package = package(&request());
    package.metadata.expires = Utc::now().date_naive();
    assert!(app.bulk_enrollment_access_token(&package).await.is_err());
    assert!(server.requests().is_empty());
    package.metadata.expires += chrono::Duration::days(30);
    for _ in 0..3 {
        assert!(app.bulk_enrollment_access_token(&package).await.is_err());
        assert!(app.transport_key.is_none());
        assert!(app.cert_key.is_none());
    }
}

// Issue a synthetic device certificate for the submitted CSR, so the test
// exercises TPM finalization and verifies that two installations get unique keys.
fn registration_response(request: &Request) -> String {
    if request.target.contains("/oauth2/token") {
        return json_response(&json!({"access_token": "synthetic-drs-access"}));
    }
    if request.target.contains("/Discover") {
        return json_response(&json!({
            "DeviceJoinService": {
                "JoinEndpoint": "$BASE/EnrollmentServer/device/",
                "ServiceVersion": "2.0",
            },
        }));
    }
    assert_eq!(
        request.target,
        "POST /EnrollmentServer/device/?api-version=2.0",
    );
    let body: Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(body["DeviceType"], "Linux");
    assert_eq!(body["JoinType"], 0);
    let csr = X509Req::from_der(
        &STANDARD.decode(body["CertificateRequest"]["Data"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", &Uuid::new_v4().to_string()).unwrap();
    let name = name.build();
    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&csr.public_key().unwrap()).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    json_response(&json!({
        "Certificate": {"RawBody": STANDARD.encode(cert.build().to_der().unwrap())},
    }))
}

#[tokio::test]
async fn two_installations_share_package_but_get_distinct_device_identities() {
    let server = Server::start_with_handler(registration_response).await;
    let package = package(&request());
    let mut identities = Vec::new();
    for _ in 0..2 {
        let mut tpm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::generate().unwrap();
        let auth_value = AuthValue::from_str(&auth_value).unwrap();
        let loadable = tpm.root_storage_key_create(&auth_value).unwrap();
        let storage_key = tpm.root_storage_key_load(&auth_value, &loadable).unwrap();
        let attrs = EnrollAttrs::new(
            "example.test".into(),
            Some("installation".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let mut app = broker(&server);
        let (transport, cert, device_id) = app
            .enroll_device_with_bulk_package(&package, attrs, &mut tpm, &storage_key)
            .await
            .unwrap();
        assert!(app.transport_key.is_some());
        assert!(app.cert_key.is_some());
        let transport = tpm.msoapxbc_rsa_key_load(&storage_key, &transport).unwrap();
        let public_key = tpm.msoapxbc_rsa_public_as_der(&transport).unwrap();
        assert!(tpm.ms_device_enrolment_key_load(&storage_key, &cert).is_ok());
        identities.push((device_id, public_key));
    }
    assert_ne!(identities[0].0, identities[1].0);
    assert_ne!(identities[0].1, identities[1].1);
    assert_eq!(package.refresh_token(), "synthetic-bprt");
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    for request in requests {
        if request.target.contains("/oauth2/token") {
            assert!(request.body.contains("synthetic-bprt"));
        } else {
            assert!(!request.body.contains("synthetic-bprt"));
            assert!(request.headers.contains("Bearer synthetic-drs-access"));
        }
    }
}

#[tokio::test]
async fn failed_reenrollment_keeps_existing_device_keys_together() {
    let mut joins = 0;
    let server = Server::start_with_handler(move |request| {
        if request.target.starts_with("POST /EnrollmentServer/device/") {
            joins += 1;
            if joins == 2 {
                return "403 Forbidden\r\n\r\nSynthetic join denied".into();
            }
        }
        registration_response(request)
    })
    .await;
    let mut tpm = BoxedDynTpm::new(SoftTpm::new());
    let auth_value = AuthValue::from_str(&AuthValue::generate().unwrap()).unwrap();
    let loadable = tpm.root_storage_key_create(&auth_value).unwrap();
    let storage_key = tpm.root_storage_key_load(&auth_value, &loadable).unwrap();
    let package = package(&request());
    let attrs = EnrollAttrs::new(
        "example.test".into(),
        Some("installation".into()),
        None,
        None,
        None,
    )
    .unwrap();
    let mut app = broker(&server);
    app.enroll_device_with_bulk_package(&package, attrs.clone(), &mut tpm, &storage_key)
        .await
        .unwrap();
    let old_transport = serde_json::to_value(&app.transport_key).unwrap();
    let old_cert = serde_json::to_value(&app.cert_key).unwrap();
    assert!(app
        .enroll_device_with_bulk_package(&package, attrs, &mut tpm, &storage_key)
        .await
        .is_err());
    assert_eq!(serde_json::to_value(&app.transport_key).unwrap(), old_transport);
    assert_eq!(serde_json::to_value(&app.cert_key).unwrap(), old_cert);
}
