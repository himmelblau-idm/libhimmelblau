/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
use crate::auth::UserToken;
use crate::error::MsalError;
use crate::graph::IntuneServiceEndpoints;
use crate::EnrollAttrs;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use kanidm_hsm_crypto::{BoxedDynTpm, KeyAlgorithm, LoadableIdentityKey, MachineKey, Tpm};
use openssl::x509::X509;
use reqwest::header;
use reqwest::redirect::Policy;
#[cfg(feature = "proxyable")]
use reqwest::Proxy;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Deserialize, Debug)]
struct EnrollmentResponse {
    #[serde(rename = "deviceId")]
    device_id: String,
    certificate: CertificateInfo,
}

#[derive(Deserialize, Debug)]
struct CertificateInfo {
    #[serde(rename = "certBlob")]
    #[serde(with = "serde_bytes")]
    cert_blob: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct IntunePolicyResponse {
    policies: Vec<IntunePolicy>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct IntunePolicy {
    #[serde(rename = "accountId")]
    account_id: String,
    description: String,
    #[serde(rename = "policyId")]
    policy_id: String,
    #[serde(rename = "policySettings")]
    policy_settings: Vec<PolicySetting>,
    #[serde(rename = "policyType")]
    policy_type: String,
    version: u32,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct PolicySetting {
    #[serde(rename = "cspPath")]
    csp_path: String,
    #[serde(rename = "cspPathId")]
    csp_path_id: String,
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "settingDefinitionItemId")]
    setting_definition_item_id: String,
    #[serde(rename = "value")]
    value: String,
}

impl From<Vec<IntunePolicy>> for IntuneStatus {
    fn from(policies: Vec<IntunePolicy>) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let formatted_date = now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
        let policy_statuses: Vec<PolicyStatus> = policies
            .into_iter()
            .map(|policy| PolicyStatus {
                policy_id: policy.policy_id,
                last_status_date_time: formatted_date.clone(),
                details: policy
                    .policy_settings
                    .into_iter()
                    .map(|setting| PolicyDetails {
                        rule_id: setting.rule_id,
                        setting_definition_item_id: setting.setting_definition_item_id,
                        expected_value: setting.value,
                        actual_value: "".to_string(),
                        error_type: None,
                        error_code: None,
                        new_compliance_state: "Error".to_string(),
                        old_compliance_state: "Unknown".to_string(),
                    })
                    .collect(),
            })
            .collect();

        IntuneStatus {
            device_id: None,
            policy_statuses,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IntuneStatus {
    #[serde(rename = "DeviceId")]
    pub device_id: Option<String>,
    #[serde(rename = "policyStatuses")]
    pub policy_statuses: Vec<PolicyStatus>,
}

impl IntuneStatus {
    pub fn set_device_id(&mut self, device_id: String) {
        self.device_id = Some(device_id)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyStatus {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "lastStatusDateTime")]
    pub last_status_date_time: String,
    pub details: Vec<PolicyDetails>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyDetails {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "settingDefinitionItemId")]
    pub setting_definition_item_id: String,
    #[serde(rename = "expectedValue")]
    pub expected_value: String,
    #[serde(rename = "actualValue")]
    pub actual_value: String,
    #[serde(rename = "errorType", skip_serializing_if = "Option::is_none")]
    pub error_type: Option<i32>,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(rename = "newComplianceState")]
    pub new_compliance_state: String,
    #[serde(rename = "oldComplianceState")]
    pub old_compliance_state: String,
}

impl PolicyDetails {
    pub fn set_status(
        &mut self,
        expected_value: Option<String>,
        actual_value: Option<String>,
        compliant: bool,
    ) {
        if let Some(expected_value) = expected_value {
            self.expected_value = expected_value;
        }
        if let Some(actual_value) = actual_value {
            self.actual_value = actual_value;
        }
        if compliant {
            self.new_compliance_state = "Compliant".to_string();
        }
    }
}
pub struct IntuneForLinux {
    client: reqwest::Client,
    service_endpoints: IntuneServiceEndpoints,
}

// Microsoft requires that the app version match a version of their Intune Portal for Linux.
static APP_VERSION: &str = "1.2405.17";

impl IntuneForLinux {
    pub fn new(service_endpoints: IntuneServiceEndpoints) -> Result<Self, MsalError> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3))
            .redirect(Policy::none())
            .cookie_store(true);

        #[cfg(feature = "proxyable")]
        {
            if let Some(proxy_var) = std::env::var("HTTPS_PROXY")
                .ok()
                .or_else(|| std::env::var("ALL_PROXY").ok())
            {
                let proxy = Proxy::https(proxy_var)
                    .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
                builder = builder.proxy(proxy).danger_accept_invalid_certs(true);
            }
        }

        let client = builder
            .build()
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;

        Ok(IntuneForLinux {
            client,
            service_endpoints,
        })
    }

    pub async fn enroll(
        &self,
        token: &UserToken,
        attrs: &EnrollAttrs,
        device_id: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(LoadableIdentityKey, String), MsalError> {
        let enrollment_url = Url::parse_with_params(
            &format!(
                "{}/enroll",
                &self.service_endpoints.get("LinuxEnrollmentService")?
            ),
            &[
                ("api-version", "1.0".to_string()),
                ("client-version", APP_VERSION.to_string()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access token must be for the resource d4ebce55-015a-49b5-a083-c84d1797ae8c
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure("Failed to Intune enroll: missing access_token".to_string())
        })?;

        // Create the Intune cert key
        let loadable_cert_key = tpm
            .identity_key_create(machine_key, None, KeyAlgorithm::Rsa2048)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating certificate key: {:?}", e)))?;

        // Create the CSR
        let csr_der = match tpm.identity_key_certificate_request(
            machine_key,
            None,
            &loadable_cert_key,
            device_id,
        ) {
            Ok(csr_der) => csr_der,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed creating CSR: {:?}", e))),
        };

        let payload = json!({
            "CertificateSigningRequest": STANDARD.encode(csr_der),
            "AppVersion": APP_VERSION,
            "DeviceName": &attrs.device_display_name,
        });

        let resp = self
            .client
            .post(enrollment_url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: EnrollmentResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            let cert_pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                base64::engine::general_purpose::STANDARD.encode(&json_resp.certificate.cert_blob)
            );
            let cert = X509::from_pem(cert_pem.as_bytes())
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?;
            let new_loadable_cert_key = match tpm.identity_key_associate_certificate(
                machine_key,
                None,
                &loadable_cert_key,
                &cert
                    .to_der()
                    .map_err(|e| MsalError::TPMFail(format!("{}", e)))?,
            ) {
                Ok(loadable_cert_key) => loadable_cert_key,
                Err(e) => {
                    return Err(MsalError::TPMFail(format!(
                        "Failed creating loadable identity key: {:?}",
                        e
                    )))
                }
            };
            Ok((new_loadable_cert_key, json_resp.device_id))
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    pub async fn details(
        &self,
        token: &UserToken,
        attrs: &EnrollAttrs,
        intune_device_id: &str,
    ) -> Result<(), MsalError> {
        let checkin_url = Url::parse_with_params(
            &format!(
                "{}/details",
                &self.service_endpoints.get("LinuxDeviceCheckinService")?
            ),
            &[
                ("api-version", "1.0".to_string()),
                ("client-version", APP_VERSION.to_string()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to update device details: missing access_token".to_string(),
            )
        })?;

        let payload = json!({
            "DeviceId": intune_device_id,
            "DeviceName": &attrs.device_display_name,
            "Manufacturer": &attrs.manufacturer,
            "OSDistribution": &attrs.os_distribution,
            "OSVersion": &attrs.os_version
        });

        let resp = self
            .client
            .post(checkin_url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn status(
        &self,
        token: &UserToken,
        payload: IntuneStatus,
    ) -> Result<IntuneStatus, MsalError> {
        let status_url = Url::parse_with_params(
            &format!(
                "{}/status",
                &self.service_endpoints.get("LinuxDeviceCheckinService")?
            ),
            &[
                ("api-version", "1.0".to_string()),
                ("client-version", APP_VERSION.to_string()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to set device status: missing access_token".to_string(),
            )
        })?;

        let resp = self
            .client
            .post(status_url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;

        if resp.status().is_success() {
            let status_resp: IntuneStatus = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(status_resp)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn policies(
        &self,
        token: &UserToken,
        intune_device_id: &str,
    ) -> Result<Vec<IntunePolicy>, MsalError> {
        let url = Url::parse_with_params(
            &format!(
                "{}/policies/{}",
                &self.service_endpoints.get("LinuxDeviceCheckinService")?,
                intune_device_id,
            ),
            &[
                ("api-version", "1.0".to_string()),
                ("client-version", APP_VERSION.to_string()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access_token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to list device policies: missing access_token".to_string(),
            )
        })?;

        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;

        if resp.status().is_success() {
            let json_resp: IntunePolicyResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp.policies)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }
}
