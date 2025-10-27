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
use crypto_glue::traits::EncodeDer;
use kanidm_hsm_crypto::{
    provider::{BoxedDynTpm, TpmMsExtensions},
    structures::{LoadableMsDeviceEnrolmentKey, StorageKey as MachineKey},
};
use openssl::x509::X509;
#[cfg(feature = "intune_portal_vers_selection")]
use regex::Regex;
use reqwest::header;
use reqwest::redirect::Policy;
#[cfg(feature = "proxyable")]
use reqwest::Proxy;
use reqwest::Url;
#[cfg(feature = "intune_portal_vers_selection")]
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "intune_portal_vers_selection")]
use std::collections::BTreeSet;
#[cfg(feature = "intune_portal_vers_selection")]
use std::error::Error;
use std::{fmt, time::Duration};

#[derive(Debug, Deserialize)]
pub struct DeviceAction {
    #[serde(rename = "target")]
    pub target: String,
    #[serde(rename = "title")]
    pub title: String,
}

#[derive(Debug, Deserialize)]
pub struct NoncompliantRule {
    #[serde(rename = "ComplianceSource")]
    pub compliance_source: Option<String>,
    #[serde(rename = "ExpectedValue")]
    pub expected_value: Option<String>,
    #[serde(rename = "RemediationOwner")]
    pub remediation_owner: Option<u8>,
    #[serde(rename = "SettingID")]
    pub setting_id: String,

    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "MoreInfoUri")]
    pub more_info_uri: Option<String>,
    #[serde(rename = "Title")]
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    #[serde(rename = "#CommonContainer.CheckCompliance")]
    pub check_compliance: DeviceAction,
    #[serde(rename = "#CommonContainer.GetManagementState")]
    pub get_management_state: DeviceAction,
    #[serde(rename = "#CommonContainer.RegisterForAppPushNotifications")]
    pub register_for_app_push_notifications: DeviceAction,
    #[serde(rename = "#CommonContainer.RemoveSignedDeviceIdPolicyAssignment")]
    pub remove_signed_device_id_policy_assignment: DeviceAction,
    #[serde(rename = "#CommonContainer.Retire")]
    pub retire: Option<DeviceAction>,
    #[serde(rename = "#CommonContainer.SetHeartBeat")]
    pub set_heartbeat: DeviceAction,
    #[serde(rename = "#CommonContainer.SetOptIn")]
    pub set_opt_in: DeviceAction,
    #[serde(rename = "#CommonContainer.SetRD")]
    pub set_rd: DeviceAction,
    #[serde(rename = "#CommonContainer.UpdateAadId")]
    pub update_aad_id: DeviceAction,

    #[serde(rename = "AadId")]
    pub aad_id: String,
    #[serde(rename = "AppWrapperCertSN")]
    pub app_wrapper_cert_sn: Option<String>,
    #[serde(rename = "Architecture")]
    pub architecture: Option<String>,
    #[serde(rename = "CategoryId")]
    pub category_id: Option<String>,
    #[serde(rename = "CategorySetByEndUser")]
    pub category_set_by_end_user: bool,
    #[serde(rename = "ChassisType")]
    pub chassis_type: String,
    #[serde(rename = "CoManagementFeatures")]
    pub co_management_features: u32,
    #[serde(rename = "ComplianceState")]
    pub compliance_state: ComplianceState,
    #[serde(rename = "CreatedDate")]
    pub created_date: String,
    #[serde(rename = "DeviceActions")]
    pub device_actions: Vec<serde_json::Value>,
    #[serde(rename = "DeviceHWId")]
    pub device_hw_id: Option<String>,
    #[serde(rename = "EasId")]
    pub eas_id: String,
    #[serde(rename = "EnrollmentType")]
    pub enrollment_type: u8,
    #[serde(rename = "ExchangeActivationItemEasId")]
    pub exchange_activation_item_eas_id: String,
    #[serde(rename = "ExchangeActivationItems")]
    pub exchange_activation_items: Vec<serde_json::Value>,
    #[serde(rename = "InGracePeriodUntilDateTimeUtc")]
    pub in_grace_period_until: String,
    #[serde(rename = "IsCompliantInGraph")]
    pub is_compliant_in_graph: bool,
    #[serde(rename = "IsExchangeActivated")]
    pub is_exchange_activated: bool,
    #[serde(rename = "IsManagedInGraph")]
    pub is_managed_in_graph: bool,
    #[serde(rename = "IsPartnerManaged")]
    pub is_partner_managed: bool,
    #[serde(rename = "IsReadOnly")]
    pub is_read_only: bool,
    #[serde(rename = "IsSharedDevice")]
    pub is_shared_device: bool,
    #[serde(rename = "IsSspConfirmed")]
    pub is_ssp_confirmed: Option<bool>,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastContact")]
    pub last_contact: String,
    #[serde(rename = "LastContactNotification")]
    pub last_contact_notification: String,
    #[serde(rename = "ManagementAgent")]
    pub management_agent: String,
    #[serde(rename = "ManagementType")]
    pub management_type: String,
    #[serde(rename = "Manufacturer")]
    pub manufacturer: String,
    #[serde(rename = "Model")]
    pub model: Option<String>,
    #[serde(rename = "Nickname")]
    pub nickname: Option<String>,
    #[serde(rename = "NoncompliantRules")]
    pub noncompliant_rules: Vec<NoncompliantRule>,
    #[serde(rename = "OSSubtype")]
    pub os_subtype: String,
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    #[serde(rename = "OfficialName")]
    pub official_name: String,
    #[serde(rename = "OperatingSystem")]
    pub operating_system: String,
    #[serde(rename = "OperatingSystemId")]
    pub operating_system_id: String,
    #[serde(rename = "OwnerType")]
    pub owner_type: u8,
    #[serde(rename = "PartnerLocalizedSelfServicePortalName")]
    pub partner_localized_ssp_name: Option<String>,
    #[serde(rename = "PartnerName")]
    pub partner_name: Option<String>,
    #[serde(rename = "PartnerRemediationUrl")]
    pub partner_remediation_url: Option<String>,
    #[serde(rename = "PartnerSelfServicePortalUrl")]
    pub partner_ssp_url: Option<String>,
    #[serde(rename = "RemotableProperties")]
    pub remotable_properties: Option<serde_json::Value>,
    #[serde(rename = "RemoteSessionUri")]
    pub remote_session_uri: Option<String>,
    #[serde(rename = "SupervisedStatus")]
    pub supervised_status: u8,
    #[serde(rename = "UdaStatus")]
    pub uda_status: u8,
    #[serde(rename = "UserApprovedEnrollment")]
    pub user_approved_enrollment: u8,
    #[serde(rename = "odata.id")]
    pub odata_id: String,
    #[serde(rename = "odata.metadata")]
    pub odata_metadata: String,
}

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
                        new_compliance_state: ComplianceState::NonCompliant.to_string(),
                        old_compliance_state: ComplianceState::Unknown.to_string(),
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ComplianceState {
    Compliant,
    #[serde(rename = "Noncompliant")]
    NonCompliant,
    Unknown,
    Error,
}

impl fmt::Display for ComplianceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ComplianceState::Compliant => "Compliant",
            ComplianceState::NonCompliant => "NonCompliant",
            ComplianceState::Unknown => "Unknown",
            ComplianceState::Error => "Error",
        };
        write!(f, "{s}")
    }
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
        compliant: &ComplianceState,
    ) {
        if let Some(expected_value) = expected_value {
            self.expected_value = expected_value;
        }
        if let Some(actual_value) = actual_value {
            self.actual_value = actual_value;
        }
        self.new_compliance_state = compliant.to_string();
    }
}
pub struct IntuneForLinux {
    client: reqwest::Client,
    app_vers: String,
    service_endpoints: IntuneServiceEndpoints,
}

#[cfg(feature = "intune_portal_vers_selection")]
pub const DEFAULT_URL: &str =
    "https://packages.microsoft.com/ubuntu/24.04/prod/pool/main/i/intune-portal/";

/// Fetch and parse available `intune-portal` versions, sorted with semver.
#[cfg(feature = "intune_portal_vers_selection")]
pub async fn fetch_intune_portal_versions(
    url: Option<&str>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let url = url.unwrap_or(DEFAULT_URL);

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
            let proxy = Proxy::https(proxy_var)?;
            builder = builder.proxy(proxy).danger_accept_invalid_certs(true);
        }
    }

    let client = builder.build()?;

    let body = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let re = Regex::new(r#"intune-portal_(\d+\.\d+\.\d+)-[A-Za-z0-9._-]+\.deb"#)?;

    let mut set: BTreeSet<Version> = BTreeSet::new();

    for caps in re.captures_iter(&body) {
        if let Some(m) = caps.get(1) {
            if let Ok(v) = Version::parse(m.as_str()) {
                set.insert(v);
            }
        }
    }

    // Map back to strings, already sorted ascending.
    Ok(set.into_iter().map(|v| v.to_string()).collect())
}

// Microsoft requires that the app version match a version of their Intune Portal for Linux.
static APP_VERSION: &str = "1.2511.7";

impl IntuneForLinux {
    pub fn new(
        service_endpoints: IntuneServiceEndpoints,
        #[cfg(feature = "intune_portal_vers_selection")] app_vers: Option<&str>,
    ) -> Result<Self, MsalError> {
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

        #[cfg(feature = "intune_portal_vers_selection")]
        let app_vers = app_vers.unwrap_or(APP_VERSION).to_string();
        #[cfg(not(feature = "intune_portal_vers_selection"))]
        let app_vers = APP_VERSION.to_string();

        Ok(IntuneForLinux {
            client,
            app_vers,
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
    ) -> Result<(LoadableMsDeviceEnrolmentKey, String), MsalError> {
        let enrollment_url = Url::parse_with_params(
            &format!(
                "{}/enroll",
                &self.service_endpoints.get("LinuxEnrollmentService")?
            ),
            &[
                ("api-version", "1.0".to_string()),
                ("client-version", self.app_vers.clone()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access token must be for the resource d4ebce55-015a-49b5-a083-c84d1797ae8c
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure("Failed to Intune enroll: missing access_token".to_string())
        })?;

        // Create the CSR
        let (in_progess_enrolment, csr) = tpm
            .ms_device_enrolment_begin(machine_key, device_id)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating certificate key: {:?}", e)))?;

        // We need to make the csr into der here, or we can can just yield the der from ms_device_enrolment_begining.
        let csr_der = csr
            .to_der()
            .map_err(|e| MsalError::CryptoFail(format!("Failed creating CSR: {:?}", e)))?;

        let payload = json!({
            "CertificateSigningRequest": STANDARD.encode(csr_der),
            "AppVersion": &self.app_vers,
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
            let cert_der = cert
                .to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?;
            // To help prevent mismatches between the tpm crypto lib and openssl, we
            // want the certificate *der* here. This way you don't have to worry about it
            // as much when you load, and it saves you having to do the translation.
            let new_loadable_cert_key = tpm
                .ms_device_enrolment_finalise(machine_key, in_progess_enrolment, &cert_der)
                .map_err(|err| {
                    MsalError::TPMFail(format!("Failed creating loadable identity key: {:?}", err))
                })?;
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
                ("client-version", self.app_vers.clone()),
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
                ("client-version", self.app_vers.clone()),
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
                ("client-version", self.app_vers.clone()),
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

    pub async fn get_compliance_info(
        &self,
        token: &UserToken,
        intune_device_id: &str,
    ) -> Result<DeviceInfo, MsalError> {
        let url = Url::parse_with_params(
            &format!(
                "{}/Devices(guid'{}')",
                &self.service_endpoints.get("IWService")?,
                intune_device_id,
            ),
            &[
                ("api-version", "16.4".to_string()),
                ("ssp", "LinuxCP".to_string()),
                ("ssp-version", self.app_vers.clone()),
                ("os", "Linux".to_string()),
                ("mgmt-agent", "mdm".to_string()),
            ],
        )
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        // The access token must be for the resource b8066b99-6e67-41be-abfa-75db1a2c8809
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to check compliance: missing access_token".to_string(),
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
            let json_resp: DeviceInfo = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }
}
