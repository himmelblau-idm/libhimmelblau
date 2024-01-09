use crate::discovery::{
    discover_enrollment_services, DISCOVERY_URL, DRS_CLIENT_NAME_HEADER_FIELD,
    DRS_CLIENT_VERSION_HEADER_FIELD,
};
use crate::error::MsalError;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use kanidm_hsm_crypto::{BoxedDynTpm, LoadableIdentityKey, MachineKey, Tpm};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use os_release::OsRelease;
use reqwest::{header, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty};
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Certificate {
    #[serde(rename = "RawBody")]
    raw_body: String,
}

#[derive(Debug, Deserialize)]
struct DRSResponse {
    #[serde(rename = "Certificate")]
    certificate: Certificate,
}

#[derive(Serialize, Clone, Default)]
struct JoinPayload {}

pub async fn register_device(
    access_token: &str,
    domain: &str,
    machine_key: &MachineKey,
    tpm: &mut BoxedDynTpm,
    certificate_id_key: &LoadableIdentityKey,
) -> Result<(LoadableIdentityKey, String), MsalError> {
    let client = reqwest::Client::new();
    let enrollment_services = discover_enrollment_services(&client, access_token, domain).await?;
    let (join_endpoint, service_version) = match enrollment_services.device_join_service {
        Some(device_join_service) => {
            let join_endpoint = match device_join_service.endpoint {
                Some(join_endpoint) => join_endpoint,
                None => format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
            };
            let service_version = match device_join_service.service_version {
                Some(service_version) => service_version,
                None => "2.0".to_string(),
            };
            (join_endpoint, service_version)
        }
        None => (
            format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
            "2.0".to_string(),
        ),
    };

    let url = Url::parse_with_params(&join_endpoint, &[("api-version", service_version)])
        .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

    let host: String = match hostname::get()
        .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
        .to_str()
    {
        Some(host) => String::from(host),
        None => {
            return Err(MsalError::GeneralFailure(
                "Failed to get machine hostname for enrollment".to_string(),
            ))
        }
    };

    let os_release = OsRelease::new().map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;

    // Create the CSR
    let csr_der = match tpm.identity_key_certificate_request(
        machine_key,
        certificate_id_key,
        "7E980AD9-B86D-4306-9425-9AC066FB014A",
    ) {
        Ok(csr_der) => csr_der,
        Err(e) => return Err(MsalError::TPMFail(format!("Failed creating CSR: {:?}", e))),
    };

    // Load the transport key
    let id_key = match tpm.identity_key_load(machine_key, certificate_id_key) {
        Ok(id_key) => id_key,
        Err(e) => {
            return Err(MsalError::TPMFail(format!(
                "Failed loading id key: {:?}",
                e
            )))
        }
    };
    let transport_key_der = match tpm.identity_key_public_as_der(&id_key) {
        Ok(transport_key_pem) => transport_key_pem,
        Err(e) => {
            return Err(MsalError::TPMFail(format!(
                "Failed getting transport key as der: {:?}",
                e
            )))
        }
    };
    let transport_key_rsa = Rsa::public_key_from_der(&transport_key_der)
        .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;
    let transport_key_rsa_ref = transport_key_rsa.as_ref();
    let jwk = json!({
        "kty": "RSA",
        "kid": Uuid::new_v4(),
        "e": URL_SAFE_NO_PAD.encode(transport_key_rsa_ref.e().to_vec()),
        "n": URL_SAFE_NO_PAD.encode(transport_key_der)
    });
    let encoded_stk = URL_SAFE.encode(jwk.to_string());

    let payload = json!({
        "CertificateRequest": {
            "Type": "pkcs10",
            "Data": STANDARD.encode(csr_der)
        },
        "DeviceDisplayName": host,
        "DeviceType": "Linux",
        "JoinType": 0,
        "OSVersion": format!("{} {}", os_release.pretty_name, os_release.version_id),
        "TargetDomain": domain,
        "TransportKey": encoded_stk,
        "Attributes": {
            "ReuseDevice": "true",
            "ReturnClientSid": "true"
        }
    });
    if let Ok(pretty) = to_string_pretty(&payload) {
        debug!("POST {}: {}", url, pretty);
    }
    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::CONTENT_TYPE, "application/json")
        .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
        .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .json(&payload)
        .send()
        .await
        .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
    if resp.status().is_success() {
        let res: DRSResponse = resp
            .json()
            .await
            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
        let loadable_id_key = match tpm.identity_key_associate_certificate(
            machine_key,
            certificate_id_key,
            &STANDARD
                .decode(res.certificate.raw_body.clone())
                .map_err(|e| MsalError::InvalidBase64(format!("{}", e)))?,
        ) {
            Ok(loadable_id_key) => loadable_id_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed creating loadable identity key: {:?}",
                    e
                )))
            }
        };
        let cert = X509::from_pem(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                res.certificate.raw_body
            )
            .as_bytes(),
        )
        .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
        let subject_name = cert.subject_name();
        let device_id = match subject_name.entries().next() {
            Some(entry) => entry
                .data()
                .as_utf8()
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            None => {
                return Err(MsalError::GeneralFailure(
                    "The device id was missing from the certificate response".to_string(),
                ))
            }
        };
        Ok((loadable_id_key, device_id.to_string()))
    } else {
        Err(MsalError::GeneralFailure(
            resp.text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
        ))
    }
}
