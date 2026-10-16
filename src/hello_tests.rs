//! Hello for Business provisioning and token acquisition against the scripted
//! test server, using a SoftTPM device identity.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::test_server::{isolated_client, json_response, Request, Server};
use super::*;
use compact_jwt::crypto::{JweA256GCMEncipher, JweRSAOAEPEncipher};
use compact_jwt::jwe::JweBuilder;
use compact_jwt::traits::JweEncipherInnerA256;
use kanidm_hsm_crypto::{provider::SoftTpm, structures::LoadableMachineKey, AuthValue};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    sign::Verifier,
    x509::{X509Builder, X509NameBuilder, X509Req},
};
use std::sync::OnceLock;

const PIN: &str = "123456";
const USERNAME: &str = "user@example.test";
const TENANT_ID: &str = "6973bb37-65f8-440e-b39e-dd57da64f6cf";

const ACQUISITION: [&str; 6] = [
    "POST /oauth2/token",
    "POST /oauth2/token",
    "POST /oauth2/token",
    "POST /oauth2/token",
    "GET /oauth2/authorize",
    "POST /oauth2/token",
];

const PROVISIONING: [&str; 7] = [
    "GET /6973bb37-65f8-440e-b39e-dd57da64f6cf/Discover",
    "POST /oauth2/token",
    "POST /oauth2/token",
    "POST /oauth2/token",
    "GET /oauth2/authorize",
    "POST /oauth2/token",
    "POST /EnrollmentServer/key/",
];

/// Key material for an enrolled device: a machine key, a transport key, a
/// device certificate issued by a test CA, and a Hello key. Generated once,
/// because software RSA key generation is slow in debug builds.
struct Identity {
    auth_value: String,
    machine_key: LoadableMachineKey,
    transport_key: LoadableMsOapxbcRsaKey,
    cert_key: LoadableMsDeviceEnrolmentKey,
    hello_key: LoadableMsHelloKey,
}

fn identity() -> &'static Identity {
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let mut tpm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::generate().unwrap();
        let loadable_machine_key = tpm
            .root_storage_key_create(&AuthValue::from_str(&auth_value).unwrap())
            .unwrap();
        let machine_key = tpm
            .root_storage_key_load(
                &AuthValue::from_str(&auth_value).unwrap(),
                &loadable_machine_key,
            )
            .unwrap();
        let transport_key = tpm.msoapxbc_rsa_key_create(&machine_key).unwrap();
        let (enrolment, csr) = tpm
            .ms_device_enrolment_begin(&machine_key, "synthetic-device")
            .unwrap();
        let cert_der = issue_certificate(&csr.to_der().unwrap());
        let cert_key = tpm
            .ms_device_enrolment_finalise(&machine_key, enrolment, &cert_der)
            .unwrap();
        let hello_key = tpm
            .ms_hello_key_create(&machine_key, &PinValue::new(PIN).unwrap())
            .unwrap();
        Identity {
            auth_value,
            machine_key: loadable_machine_key,
            transport_key,
            cert_key,
            hello_key,
        }
    })
}

/// The enrolled device, loaded into its own SoftTPM.
struct Device {
    tpm: BoxedDynTpm,
    machine_key: StorageKey,
}

impl Device {
    fn new() -> Self {
        let identity = identity();
        let mut tpm = BoxedDynTpm::new(SoftTpm::new());
        let machine_key = tpm
            .root_storage_key_load(
                &AuthValue::from_str(&identity.auth_value).unwrap(),
                &identity.machine_key,
            )
            .unwrap();
        Device { tpm, machine_key }
    }

    fn app(&self, url: &str) -> BrokerClientApplication {
        let identity = identity();
        let mut app = BrokerClientApplication::new(
            Some(url),
            None,
            Some(identity.transport_key.clone()),
            Some(identity.cert_key.clone()),
            #[cfg(feature = "set_timeout")]
            Duration::from_secs(3),
            #[cfg(feature = "ipvers")]
            &[],
        )
        .unwrap();
        app.app.app.client = isolated_client(&app.app.app.jar);
        app.discovery_url = Some(url.to_string());
        app
    }

    /// A session key JWE encrypted to the transport key, as returned with a PRT.
    fn session_key_jwe(&mut self) -> String {
        let transport_key = self
            .tpm
            .msoapxbc_rsa_key_load(&self.machine_key, &identity().transport_key)
            .unwrap();
        let public_key = self.tpm.rs256_public(&transport_key).unwrap();
        JweA256GCMEncipher::new_ephemeral()
            .unwrap()
            .encipher_inner(
                &JweRSAOAEPEncipher::from(public_key),
                &JweBuilder::from(Vec::new()).build(),
            )
            .unwrap()
            .to_string()
    }

    fn hello_key(&self) -> LoadableMsHelloKey {
        identity().hello_key.clone()
    }

    fn load(&mut self, hello_key: &LoadableMsHelloKey) -> LoadedMsHelloKey {
        LoadedMsHelloKey::load(hello_key, PIN, &mut self.tpm, &self.machine_key).unwrap()
    }

    /// The public key as registered with the key provisioning service.
    fn kngc(&mut self, hello_key: &LoadedMsHelloKey) -> String {
        let der = self
            .tpm
            .ms_hello_rsa_public_as_der(&hello_key.signing_key)
            .unwrap();
        let rsa = Rsa::public_key_from_der(&der).unwrap();
        let blob: Vec<u8> = BcryptRsaKeyBlob::new(2048, &rsa.e().to_vec(), &rsa.n().to_vec())
            .try_into()
            .unwrap();
        STANDARD.encode(blob)
    }

    fn signed_by(&mut self, hello_key: &LoadedMsHelloKey, jwt: &str) -> bool {
        let der = self
            .tpm
            .ms_hello_rsa_public_as_der(&hello_key.signing_key)
            .unwrap();
        let public_key = PKey::public_key_from_der(&der).unwrap();
        let (signing_input, signature) = jwt.rsplit_once('.').unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
        verifier.update(signing_input.as_bytes()).unwrap();
        verifier
            .verify(&URL_SAFE_NO_PAD.decode(signature).unwrap())
            .unwrap()
    }

    fn prt_refresh_token(
        &mut self,
        app: &BrokerClientApplication,
        sealed_prt: &SealedData,
    ) -> String {
        let transport_key = app.transport_key(&mut self.tpm, &self.machine_key).unwrap();
        let cek = self.tpm.rs256_yield_cek(&transport_key);
        let prt_storage_key = cek.as_ref().unwrap_or(&self.machine_key);
        app.unseal_user_prt(sealed_prt, &mut self.tpm, prt_storage_key)
            .unwrap()
            .refresh_token
            .clone()
    }
}

fn issue_certificate(csr_der: &[u8]) -> Vec<u8> {
    let csr = X509Req::from_der(csr_der).unwrap();
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut issuer = X509NameBuilder::new().unwrap();
    issuer.append_entry_by_text("CN", "Synthetic CA").unwrap();
    let issuer = issuer.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(csr.subject_name()).unwrap();
    builder.set_issuer_name(&issuer).unwrap();
    builder.set_pubkey(&csr.public_key().unwrap()).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

fn nonce(value: &str) -> String {
    json_response(&json!({ "Nonce": value }))
}

fn prt(session_key_jwe: &str) -> String {
    json_response(&json!({
        "token_type": "Bearer",
        "expires_in": "1209599",
        "ext_expires_in": "0",
        "expires_on": "9999999999",
        "refresh_token": "synthetic-prt-refresh",
        "refresh_token_expires_in": 1209599,
        "session_key_jwe": session_key_jwe,
        "id_token": {
            "name": "Synthetic User",
            "oid": "d0f8b3a7-1c2e-4f5a-9b6c-7d8e9f0a1b2c",
            "preferred_username": USERNAME,
            "tid": TENANT_ID
        }
    }))
}

fn authorization_code() -> String {
    "302 Found\r\nLocation: https://example.test/callback?code=synthetic-code\r\nContent-Type: text/html\r\n\r\n<a href=\"https://example.test/callback?code=synthetic-code\">continue</a>".into()
}

fn access_token() -> String {
    json_response(&json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "ext_expires_in": 3600,
        "access_token": "synthetic-access",
        "refresh_token": "synthetic-refresh"
    }))
}

fn error_response() -> String {
    "400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"invalid_request\",\"error_description\":\"synthetic failure\",\"error_codes\":[90014]}".into()
}

fn acquisition(session_key_jwe: &str) -> Vec<String> {
    vec![
        nonce("nonce-1"),
        nonce("nonce-2"),
        prt(session_key_jwe),
        nonce("nonce-3"),
        authorization_code(),
        access_token(),
    ]
}

fn provisioning(session_key_jwe: &str) -> Vec<String> {
    vec![
        json_response(&json!({
            "KeyProvisioningService": {
                "KeyProvisionEndpoint": "$BASE/EnrollmentServer/key/",
                "KeyProvisionResourceId": "urn:ms-drs:enterpriseregistration.windows.net",
                "ServiceVersion": "1.0"
            }
        })),
        nonce("nonce-1"),
        prt(session_key_jwe),
        nonce("nonce-2"),
        authorization_code(),
        access_token(),
        json_response(&json!({})),
    ]
}

/// A token as obtained by an MFA sign-in, which permits Hello key provisioning.
fn user_token(amr: &[&str]) -> UserToken {
    let payload = json!({ "amr": amr, "tid": TENANT_ID });
    let access_token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    serde_json::from_value(json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "ext_expires_in": 3600,
        "access_token": access_token,
        "refresh_token": "synthetic-refresh"
    }))
    .unwrap()
}

fn targets(requests: &[Request]) -> Vec<&str> {
    requests
        .iter()
        .map(|r| r.target.split('?').next().unwrap())
        .collect()
}

fn jwt_payload(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// The payload of a PRT request and the Hello assertion it carries.
fn prt_request(request: &Request) -> (Value, String) {
    let form: HashMap<String, String> = serde_urlencoded::from_str(&request.body).unwrap();
    let payload = jwt_payload(&form["request"]);
    let assertion = payload["assertion"].as_str().unwrap().to_string();
    (payload, assertion)
}

#[tokio::test]
async fn acquisition_signs_the_assertion_with_the_loaded_key() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let loaded = device.load(&hello_key);
    let server = Server::start(acquisition(&device.session_key_jwe())).await;
    let app = device.app(&server.url);

    let token = app
        .acquire_token_by_loaded_ms_hello_key(
            USERNAME,
            &loaded,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
        )
        .await
        .unwrap();

    assert_eq!(token.access_token.as_deref(), Some("synthetic-access"));
    assert_eq!(
        device.prt_refresh_token(&app, token.prt.as_ref().unwrap()),
        "synthetic-prt-refresh"
    );
    let requests = server.requests();
    assert_eq!(targets(&requests), ACQUISITION);
    let (payload, assertion) = prt_request(&requests[2]);
    assert_eq!(payload["username"], USERNAME);
    assert_eq!(payload["request_nonce"], "nonce-2");
    assert_eq!(jwt_payload(&assertion)["request_nonce"], "nonce-1");
    assert!(device.signed_by(&loaded, &assertion));
}

#[tokio::test]
async fn acquisition_with_the_hello_pin_matches_the_loaded_key_variant() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let loaded = device.load(&hello_key);
    let server = Server::start(acquisition(&device.session_key_jwe())).await;
    let app = device.app(&server.url);

    let token = app
        .acquire_token_by_hello_for_business_key(
            USERNAME,
            &hello_key,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await
        .unwrap();

    assert_eq!(token.access_token.as_deref(), Some("synthetic-access"));
    assert_eq!(
        device.prt_refresh_token(&app, token.prt.as_ref().unwrap()),
        "synthetic-prt-refresh"
    );
    let requests = server.requests();
    assert_eq!(targets(&requests), ACQUISITION);
    let (_, assertion) = prt_request(&requests[2]);
    assert!(device.signed_by(&loaded, &assertion));
}

#[tokio::test]
async fn acquisition_with_a_wrong_pin_fails_before_contacting_the_authority() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let server = Server::start(acquisition(&device.session_key_jwe())).await;
    let app = device.app(&server.url);

    let result = app
        .acquire_token_by_hello_for_business_key(
            USERNAME,
            &hello_key,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
            "654321",
        )
        .await;

    assert!(matches!(result, Err(MsalError::TPMFail(_))));
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn acquisition_reports_authority_errors() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let loaded = device.load(&hello_key);
    let server = Server::start(vec![error_response()]).await;
    let app = device.app(&server.url);

    let result = app
        .acquire_token_by_loaded_ms_hello_key(
            USERNAME,
            &loaded,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
        )
        .await;

    assert!(matches!(
        result,
        Err(MsalError::AcquireTokenFailed(e)) if e.error_description == "synthetic failure"
    ));
    assert_eq!(targets(&server.requests()), ["POST /oauth2/token"]);
}

#[tokio::test]
async fn acquisition_reports_an_unreachable_authority() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let loaded = device.load(&hello_key);
    let url = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let app = device.app(&url);

    let result = app
        .acquire_token_by_loaded_ms_hello_key(
            USERNAME,
            &loaded,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
        )
        .await;

    assert!(matches!(result, Err(MsalError::RequestFailed(_))));
}

#[tokio::test]
async fn acquisition_reports_a_malformed_prt_response() {
    let mut device = Device::new();
    let hello_key = device.hello_key();
    let loaded = device.load(&hello_key);
    let server = Server::start(vec![
        nonce("nonce-1"),
        nonce("nonce-2"),
        json_response(&json!({ "token_type": "Bearer" })),
    ])
    .await;
    let app = device.app(&server.url);

    let result = app
        .acquire_token_by_loaded_ms_hello_key(
            USERNAME,
            &loaded,
            vec![],
            None,
            #[cfg(feature = "on_behalf_of")]
            None,
            &mut device.tpm,
            &device.machine_key,
        )
        .await;

    assert!(matches!(result, Err(MsalError::InvalidJson(_))));
    assert_eq!(targets(&server.requests()), ACQUISITION[..3]);
}

#[tokio::test]
async fn provisioning_registers_the_loaded_key() {
    let mut device = Device::new();
    let server = Server::start(provisioning(&device.session_key_jwe())).await;
    let app = device.app(&server.url);

    let (hello_key, loaded) = app
        .provision_loaded_ms_hello_key(
            &user_token(&["pwd", "ngcmfa"]),
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await
        .unwrap();

    let requests = server.requests();
    assert_eq!(targets(&requests), PROVISIONING);
    let registration: Value = serde_json::from_str(&requests[6].body).unwrap();
    let kngc = device.kngc(&loaded);
    assert_eq!(registration["kngc"], kngc);
    let reloaded = device.load(&hello_key);
    assert_eq!(device.kngc(&reloaded), kngc);
    // Data sealed with the provisioned storage key opens with the Hello PIN.
    let sealed = device
        .tpm
        .seal_data(loaded.storage_key(), Zeroizing::new(b"synthetic".to_vec()))
        .unwrap();
    assert_eq!(
        device
            .tpm
            .unseal_data(reloaded.storage_key(), &sealed)
            .unwrap()
            .to_vec(),
        b"synthetic".to_vec()
    );
}

#[tokio::test]
async fn provisioning_with_the_hello_pin_matches_the_loaded_key_variant() {
    let mut device = Device::new();
    let server = Server::start(provisioning(&device.session_key_jwe())).await;
    let app = device.app(&server.url);

    let hello_key = app
        .provision_hello_for_business_key(
            &user_token(&["pwd", "ngcmfa"]),
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await
        .unwrap();

    let requests = server.requests();
    assert_eq!(targets(&requests), PROVISIONING);
    let registration: Value = serde_json::from_str(&requests[6].body).unwrap();
    let loaded = device.load(&hello_key);
    assert_eq!(registration["kngc"], device.kngc(&loaded));
}

#[tokio::test]
async fn provisioning_requires_an_mfa_token() {
    let mut device = Device::new();
    let server = Server::start(vec![]).await;
    let app = device.app(&server.url);

    let result = app
        .provision_loaded_ms_hello_key(
            &user_token(&["pwd"]),
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await;

    assert!(matches!(result, Err(MsalError::GeneralFailure(_))));
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn provisioning_reports_a_failed_discovery() {
    let mut device = Device::new();
    let server = Server::start(vec![
        "500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nsynthetic outage".into(),
    ])
    .await;
    let app = device.app(&server.url);

    let result = app
        .provision_loaded_ms_hello_key(
            &user_token(&["pwd", "ngcmfa"]),
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await;

    assert!(matches!(result, Err(MsalError::GeneralFailure(e)) if e == "synthetic outage"));
    assert_eq!(targets(&server.requests()), PROVISIONING[..1]);
}

#[tokio::test]
async fn provisioning_reports_a_rejected_key_registration() {
    let mut device = Device::new();
    let mut responses = provisioning(&device.session_key_jwe());
    *responses.last_mut().unwrap() = error_response();
    let server = Server::start(responses).await;
    let app = device.app(&server.url);

    let result = app
        .provision_loaded_ms_hello_key(
            &user_token(&["pwd", "ngcmfa"]),
            &mut device.tpm,
            &device.machine_key,
            PIN,
        )
        .await;

    assert!(matches!(result, Err(MsalError::GeneralFailure(_))));
    assert_eq!(targets(&server.requests()), PROVISIONING);
}
