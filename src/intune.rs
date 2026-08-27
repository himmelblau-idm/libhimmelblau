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
use base64::Engine;
use chrono::{DateTime, Utc};
use crypto_glue::traits::SpkiEncodePublicKey;
use crypto_glue::x509::oiddb::rfc5912;
use der::asn1::{BitString, SetOfVec};
use der::pem::LineEnding;
use der::{Decode, Encode, Sequence};
use kanidm_hsm_crypto::{
    provider::{BoxedDynTpm, TpmRS256},
    structures::{LoadableMsDeviceEnrolmentKey, LoadableRS256Key, StorageKey as MachineKey},
};
use openssl::x509::X509;
use os_release::OsRelease;
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
use std::fs;
use std::str::FromStr;
use std::{fmt, time::Duration};
use tokio::time::sleep;
use tracing::debug;
use uuid::Uuid;
use x509_cert::attr::Attribute;
use x509_cert::certificate::Certificate;
use x509_cert::name::Name;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

#[cfg(feature = "ipvers")]
use crate::auth::IpVersion;
#[cfg(feature = "set_timeout")]
use std::cmp::min;

#[derive(Debug, Deserialize)]
pub struct DeviceAction {
    #[serde(rename = "target", alias = "Target")]
    pub target: String,
    #[serde(rename = "title", alias = "Title")]
    pub title: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NoncompliantRule {
    #[serde(rename = "ComplianceSource", alias = "complianceSource")]
    pub compliance_source: Option<String>,
    #[serde(rename = "ExpectedValue", alias = "expectedValue")]
    pub expected_value: Option<String>,
    #[serde(rename = "RemediationOwner", alias = "remediationOwner")]
    pub remediation_owner: Option<u8>,
    #[serde(rename = "SettingID", alias = "settingID", alias = "settingId")]
    pub setting_id: String,

    #[serde(rename = "Description", alias = "description")]
    pub description: Option<String>,
    #[serde(rename = "MoreInfoUri", alias = "moreInfoUri")]
    pub more_info_uri: Option<String>,
    #[serde(rename = "Title", alias = "title")]
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    #[serde(
        rename = "#CommonContainer.CheckCompliance",
        alias = "#commonContainer.CheckCompliance"
    )]
    pub check_compliance: DeviceAction,
    #[serde(
        rename = "#CommonContainer.GetManagementState",
        alias = "#commonContainer.GetManagementState"
    )]
    pub get_management_state: DeviceAction,
    #[serde(
        rename = "#CommonContainer.RegisterForAppPushNotifications",
        alias = "#commonContainer.RegisterForAppPushNotifications"
    )]
    pub register_for_app_push_notifications: DeviceAction,
    #[serde(
        rename = "#CommonContainer.RemoveSignedDeviceIdPolicyAssignment",
        alias = "#commonContainer.RemoveSignedDeviceIdPolicyAssignment"
    )]
    pub remove_signed_device_id_policy_assignment: DeviceAction,
    #[serde(rename = "#CommonContainer.Retire", alias = "#commonContainer.Retire")]
    pub retire: Option<DeviceAction>,
    #[serde(
        rename = "#CommonContainer.SetHeartBeat",
        alias = "#commonContainer.SetHeartBeat"
    )]
    pub set_heartbeat: DeviceAction,
    #[serde(
        rename = "#CommonContainer.SetOptIn",
        alias = "#commonContainer.SetOptIn"
    )]
    pub set_opt_in: DeviceAction,
    #[serde(rename = "#CommonContainer.SetRD", alias = "#commonContainer.SetRD")]
    pub set_rd: DeviceAction,
    #[serde(
        rename = "#CommonContainer.UpdateAadId",
        alias = "#commonContainer.UpdateAadId"
    )]
    pub update_aad_id: DeviceAction,

    #[serde(rename = "AadId", alias = "aadId")]
    pub aad_id: String,
    #[serde(
        rename = "AppWrapperCertSN",
        alias = "appWrapperCertSN",
        alias = "appWrapperCertSn"
    )]
    pub app_wrapper_cert_sn: Option<String>,
    #[serde(rename = "Architecture", alias = "architecture")]
    pub architecture: Option<String>,
    #[serde(rename = "CategoryId", alias = "categoryId")]
    pub category_id: Option<String>,
    #[serde(rename = "CategorySetByEndUser", alias = "categorySetByEndUser")]
    pub category_set_by_end_user: bool,
    #[serde(rename = "ChassisType", alias = "chassisType")]
    pub chassis_type: String,
    #[serde(rename = "CoManagementFeatures", alias = "coManagementFeatures")]
    pub co_management_features: u32,
    #[serde(rename = "ComplianceState", alias = "complianceState")]
    pub compliance_state: ComplianceState,
    #[serde(rename = "CreatedDate", alias = "createdDate")]
    pub created_date: String,
    #[serde(rename = "DeviceActions", alias = "deviceActions")]
    pub device_actions: Vec<serde_json::Value>,
    #[serde(rename = "DeviceHWId", alias = "deviceHWId", alias = "deviceHwId")]
    pub device_hw_id: Option<String>,
    #[serde(rename = "EasId", alias = "easId")]
    pub eas_id: String,
    #[serde(rename = "EnrollmentType", alias = "enrollmentType")]
    pub enrollment_type: u8,
    #[serde(
        rename = "ExchangeActivationItemEasId",
        alias = "exchangeActivationItemEasId"
    )]
    pub exchange_activation_item_eas_id: String,
    #[serde(rename = "ExchangeActivationItems", alias = "exchangeActivationItems")]
    pub exchange_activation_items: Vec<serde_json::Value>,
    #[serde(
        rename = "InGracePeriodUntilDateTimeUtc",
        alias = "inGracePeriodUntilDateTimeUtc"
    )]
    pub in_grace_period_until: String,
    #[serde(rename = "IsCompliantInGraph", alias = "isCompliantInGraph")]
    pub is_compliant_in_graph: bool,
    #[serde(rename = "IsExchangeActivated", alias = "isExchangeActivated")]
    pub is_exchange_activated: bool,
    #[serde(rename = "IsManagedInGraph", alias = "isManagedInGraph")]
    pub is_managed_in_graph: bool,
    #[serde(rename = "IsPartnerManaged", alias = "isPartnerManaged")]
    pub is_partner_managed: bool,
    #[serde(rename = "IsReadOnly", alias = "isReadOnly")]
    pub is_read_only: bool,
    #[serde(rename = "IsSharedDevice", alias = "isSharedDevice")]
    pub is_shared_device: bool,
    #[serde(rename = "IsSspConfirmed", alias = "isSspConfirmed")]
    pub is_ssp_confirmed: Option<bool>,
    #[serde(rename = "Key", alias = "key")]
    pub key: String,
    #[serde(rename = "LastContact", alias = "lastContact")]
    pub last_contact: String,
    #[serde(rename = "LastContactNotification", alias = "lastContactNotification")]
    pub last_contact_notification: String,
    #[serde(rename = "ManagementAgent", alias = "managementAgent")]
    pub management_agent: String,
    #[serde(rename = "ManagementType", alias = "managementType")]
    pub management_type: String,
    #[serde(rename = "Manufacturer", alias = "manufacturer")]
    pub manufacturer: String,
    #[serde(rename = "Model", alias = "model")]
    pub model: Option<String>,
    #[serde(rename = "Nickname", alias = "nickname")]
    pub nickname: Option<String>,
    #[serde(rename = "NoncompliantRules", alias = "noncompliantRules")]
    pub noncompliant_rules: Vec<NoncompliantRule>,
    #[serde(rename = "OSSubtype", alias = "osSubtype")]
    pub os_subtype: String,
    #[serde(rename = "OSVersion", alias = "osVersion")]
    pub os_version: String,
    #[serde(rename = "OfficialName", alias = "officialName")]
    pub official_name: String,
    #[serde(rename = "OperatingSystem", alias = "operatingSystem")]
    pub operating_system: String,
    #[serde(rename = "OperatingSystemId", alias = "operatingSystemId")]
    pub operating_system_id: String,
    #[serde(rename = "OwnerType", alias = "ownerType")]
    pub owner_type: u8,
    #[serde(
        rename = "PartnerLocalizedSelfServicePortalName",
        alias = "partnerLocalizedSelfServicePortalName"
    )]
    pub partner_localized_ssp_name: Option<String>,
    #[serde(rename = "PartnerName", alias = "partnerName")]
    pub partner_name: Option<String>,
    #[serde(rename = "PartnerRemediationUrl", alias = "partnerRemediationUrl")]
    pub partner_remediation_url: Option<String>,
    #[serde(
        rename = "PartnerSelfServicePortalUrl",
        alias = "partnerSelfServicePortalUrl"
    )]
    pub partner_ssp_url: Option<String>,
    #[serde(rename = "RemotableProperties", alias = "remotableProperties")]
    pub remotable_properties: Option<serde_json::Value>,
    #[serde(rename = "RemoteSessionUri", alias = "remoteSessionUri")]
    pub remote_session_uri: Option<String>,
    #[serde(rename = "SupervisedStatus", alias = "supervisedStatus")]
    pub supervised_status: u8,
    #[serde(rename = "UdaStatus", alias = "udaStatus")]
    pub uda_status: u8,
    #[serde(rename = "UserApprovedEnrollment", alias = "userApprovedEnrollment")]
    pub user_approved_enrollment: u8,
    #[serde(rename = "odata.id", alias = "Odata.id")]
    pub odata_id: String,
    #[serde(rename = "odata.metadata", alias = "Odata.metadata")]
    pub odata_metadata: String,
}

#[derive(Deserialize, Debug)]
struct EnrollmentResponse {
    #[serde(rename = "deviceId", alias = "DeviceId")]
    device_id: String,
    #[serde(alias = "Certificate")]
    certificate: CertificateInfo,
}

#[derive(Deserialize, Debug)]
struct CertificateInfo {
    #[serde(rename = "certBlob", alias = "CertBlob")]
    #[serde(with = "serde_bytes")]
    cert_blob: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct IntunePolicyResponse {
    #[serde(alias = "Policies")]
    policies: Vec<IntunePolicy>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct IntunePolicy {
    #[serde(rename = "accountId", alias = "AccountId")]
    account_id: String,
    #[serde(alias = "Description")]
    description: String,
    #[serde(rename = "policyId", alias = "PolicyId")]
    policy_id: String,
    #[serde(rename = "policySettings", alias = "PolicySettings")]
    policy_settings: Vec<PolicySetting>,
    #[serde(rename = "policyType", alias = "PolicyType")]
    policy_type: String,
    #[serde(alias = "Version")]
    version: u32,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct PolicySetting {
    #[serde(rename = "cspPath", alias = "CspPath")]
    csp_path: String,
    #[serde(rename = "cspPathId", alias = "CspPathId")]
    csp_path_id: String,
    #[serde(rename = "ruleId", alias = "RuleId")]
    rule_id: String,
    #[serde(rename = "settingDefinitionItemId", alias = "SettingDefinitionItemId")]
    setting_definition_item_id: String,
    #[serde(rename = "value", alias = "Value")]
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
                        error_type: Some(0),
                        error_code: Some(0),
                        new_compliance_state: ComplianceState::NonCompliant.to_string(),
                        old_compliance_state: ComplianceState::Unknown.to_string(),
                        csp_path: setting.csp_path,
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
    #[serde(rename = "DeviceId", alias = "deviceId")]
    pub device_id: Option<String>,
    #[serde(rename = "PolicyStatuses", alias = "policyStatuses", default)]
    pub policy_statuses: Vec<PolicyStatus>,
}

impl IntuneStatus {
    pub fn set_device_id(&mut self, device_id: String) {
        self.device_id = Some(device_id)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatus {
    #[serde(rename = "PolicyId", alias = "policyId")]
    pub policy_id: String,
    #[serde(alias = "lastStatusDateTime")]
    pub last_status_date_time: String,
    #[serde(alias = "details")]
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
#[serde(rename_all = "PascalCase")]
pub struct PolicyDetails {
    #[serde(alias = "ruleId")]
    pub rule_id: String,
    #[serde(alias = "settingDefinitionItemId")]
    pub setting_definition_item_id: String,
    #[serde(alias = "expectedValue")]
    pub expected_value: String,
    #[serde(alias = "actualValue")]
    pub actual_value: String,
    #[serde(alias = "errorType", skip_serializing_if = "Option::is_none")]
    pub error_type: Option<i32>,
    #[serde(alias = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(alias = "newComplianceState")]
    pub new_compliance_state: String,
    #[serde(alias = "oldComplianceState")]
    pub old_compliance_state: String,
    #[serde(skip)]
    pub csp_path: String,
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
const UNKNOWN_OS_VERSION: &str = "0";
const UNKNOWN_OS_DISTRIBUTION: &str = "Linux";
const MAX_HTTP_ERROR_BODY_LEN: usize = 4096;
const INTUNE_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(5),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct IntunePlatformInfo {
    os_distribution: String,
    os_version: String,
}

impl IntunePlatformInfo {
    fn from_os_release() -> Option<Self> {
        let release = OsRelease::new().ok()?;
        Some(Self {
            os_distribution: select_trimmed_value(Some(&release.id), None, UNKNOWN_OS_DISTRIBUTION),
            os_version: select_device_state_os_version(Some(&release.version_id), None),
        })
    }

    fn for_details(attrs: &EnrollAttrs) -> Self {
        match Self::from_os_release() {
            Some(platform) => platform.with_detail_fallbacks(attrs),
            None => Self {
                os_distribution: select_trimmed_value(
                    Some(&attrs.os_distribution),
                    None,
                    UNKNOWN_OS_DISTRIBUTION,
                ),
                os_version: select_device_state_os_version(Some(&attrs.os_version), None),
            },
        }
    }

    fn current() -> Self {
        let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease").ok();
        match Self::from_os_release() {
            Some(platform) => platform,
            None => Self {
                os_distribution: UNKNOWN_OS_DISTRIBUTION.to_string(),
                os_version: select_device_state_os_version(None, kernel_version.as_deref()),
            },
        }
    }

    fn with_detail_fallbacks(mut self, attrs: &EnrollAttrs) -> Self {
        if self.os_distribution.is_empty() || self.os_distribution == UNKNOWN_OS_DISTRIBUTION {
            self.os_distribution =
                select_trimmed_value(Some(&attrs.os_distribution), None, UNKNOWN_OS_DISTRIBUTION);
        }
        if self.os_version.is_empty() || self.os_version == UNKNOWN_OS_VERSION {
            self.os_version = select_device_state_os_version(Some(&attrs.os_version), None);
        }
        self
    }
}

fn select_trimmed_value(primary: Option<&str>, fallback: Option<&str>, default: &str) -> String {
    primary
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| fallback.map(str::trim).filter(|value| !value.is_empty()))
        .unwrap_or(default)
        .to_string()
}

fn intune_user_agent(platform: &IntunePlatformInfo, app_version: &str) -> String {
    format!(
        "Linux Company Portal/{} {}/{}",
        platform.os_distribution, platform.os_version, app_version
    )
}

fn intune_architecture(architecture: &str) -> &str {
    match architecture {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        "x86" | "i686" => "X86",
        architecture => architecture,
    }
}

fn device_state_query_parameters(
    app_version: &str,
    os_version: &str,
    architecture: &str,
) -> [(&'static str, String); 8] {
    [
        ("api-version", "16.4".to_string()),
        ("ssp", "LinuxCP".to_string()),
        ("ssp-version", app_version.to_string()),
        ("os", "Linux".to_string()),
        ("os-version", os_version.to_string()),
        ("os-sub", "None".to_string()),
        ("arch", intune_architecture(architecture).to_string()),
        ("mgmt-agent", "mdm".to_string()),
    ]
}

fn select_device_state_os_version(
    distro_version: Option<&str>,
    kernel_version: Option<&str>,
) -> String {
    distro_version
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .or_else(|| {
            kernel_version
                .map(str::trim)
                .filter(|version| !version.is_empty())
        })
        .unwrap_or(UNKNOWN_OS_VERSION)
        .to_string()
}

fn checkin_url(
    checkin_service_url: &str,
    operation: &str,
    app_version: &str,
) -> Result<Url, MsalError> {
    Url::parse_with_params(
        &format!("{}/{}", checkin_service_url, operation),
        &[
            ("api-version", "1.0".to_string()),
            ("client-version", app_version.to_string()),
        ],
    )
    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))
}

fn policies_url(
    checkin_service_url: &str,
    intune_device_id: &str,
    app_version: &str,
) -> Result<Url, MsalError> {
    Url::parse_with_params(
        &format!("{}/policies/{}", checkin_service_url, intune_device_id),
        &[
            ("api-version", "1.0".to_string()),
            ("client-version", app_version.to_string()),
        ],
    )
    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))
}

fn details_payload(
    attrs: &EnrollAttrs,
    intune_device_id: &str,
    platform: &IntunePlatformInfo,
) -> serde_json::Value {
    json!({
        "DeviceId": intune_device_id,
        "DeviceName": &attrs.device_display_name,
        "Manufacturer": &attrs.manufacturer,
        "OSDistribution": &platform.os_distribution,
        "OSVersion": &platform.os_version
    })
}

fn apply_compliance_headers(
    request: reqwest::RequestBuilder,
    access_token: &str,
    platform: &IntunePlatformInfo,
    app_version: &str,
    request_id: Uuid,
) -> reqwest::RequestBuilder {
    request
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(header::USER_AGENT, intune_user_agent(platform, app_version))
        .header(header::ACCEPT, "*/*")
        .header("client-request-id", request_id.to_string())
}

fn details_request(
    client: &reqwest::Client,
    url: Url,
    access_token: &str,
    platform: &IntunePlatformInfo,
    app_version: &str,
    request_id: Uuid,
    payload: &serde_json::Value,
) -> reqwest::RequestBuilder {
    apply_compliance_headers(
        client.post(url),
        access_token,
        platform,
        app_version,
        request_id,
    )
    .header(header::CONTENT_TYPE, "application/json")
    .json(payload)
}

fn status_request(
    client: &reqwest::Client,
    url: Url,
    access_token: &str,
    platform: &IntunePlatformInfo,
    app_version: &str,
    request_id: Uuid,
    payload: &IntuneStatus,
) -> reqwest::RequestBuilder {
    apply_compliance_headers(
        client.post(url),
        access_token,
        platform,
        app_version,
        request_id,
    )
    .header(header::CONTENT_TYPE, "application/json")
    .json(payload)
}

fn policies_request(
    client: &reqwest::Client,
    url: Url,
    access_token: &str,
    platform: &IntunePlatformInfo,
    app_version: &str,
    request_id: Uuid,
) -> reqwest::RequestBuilder {
    apply_compliance_headers(
        client.get(url),
        access_token,
        platform,
        app_version,
        request_id,
    )
}

fn device_state_url(
    iwservice_url: &str,
    intune_device_id: &str,
    app_version: &str,
    os_version: &str,
    architecture: &str,
) -> Result<Url, MsalError> {
    Url::parse_with_params(
        &format!("{}/Devices(guid'{}')", iwservice_url, intune_device_id),
        &device_state_query_parameters(app_version, os_version, architecture),
    )
    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))
}

fn device_state_request(
    client: &reqwest::Client,
    url: Url,
    access_token: &str,
    platform: &IntunePlatformInfo,
    app_version: &str,
    request_id: Uuid,
) -> reqwest::RequestBuilder {
    apply_compliance_headers(
        client.get(url),
        access_token,
        platform,
        app_version,
        request_id,
    )
}

fn sanitize_http_error_body(body: &str) -> String {
    body.chars()
        .flat_map(char::escape_default)
        .take(MAX_HTTP_ERROR_BODY_LEN)
        .collect()
}

fn is_retryable_intune_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::INTERNAL_SERVER_ERROR
    )
}

fn intune_retry_delay(status: reqwest::StatusCode, retry_count: usize) -> Option<Duration> {
    if is_retryable_intune_status(status) {
        INTUNE_RETRY_DELAYS.get(retry_count).copied()
    } else {
        None
    }
}

async fn send_intune_request_with_retry<F>(
    operation: &str,
    mut build_request: F,
) -> Result<reqwest::Response, MsalError>
where
    F: FnMut() -> reqwest::RequestBuilder,
{
    let mut retry_count = 0;

    loop {
        let resp = build_request()
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;

        let status = resp.status();
        let Some(delay) = intune_retry_delay(status, retry_count) else {
            return Ok(resp);
        };

        debug!(
            "Retrying Intune {} request after {} response; retry {} of {} in {:?}",
            operation,
            status,
            retry_count + 1,
            INTUNE_RETRY_DELAYS.len(),
            delay
        );

        retry_count += 1;
        sleep(delay).await;
    }
}

async fn http_status_error(operation: &str, resp: reqwest::Response) -> MsalError {
    let status = resp.status();
    let body = match resp.text().await {
        Ok(body) => sanitize_http_error_body(&body),
        Err(e) => format!("unable to read response body: {}", e),
    };

    if body.is_empty() {
        MsalError::GeneralFailure(format!("{} request failed: {}", operation, status))
    } else {
        MsalError::GeneralFailure(format!(
            "{} request failed: {}: {}",
            operation, status, body
        ))
    }
}

/// PKCS#10 CertificationRequestInfo with an EMPTY constructed context [0] tag.
/// Microsoft requires the attributes field to be present as an empty CONSTRUCTED tag.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct CertReqInfoEmptyAttributes {
    /// Version (must be 0 for v1)
    pub version: x509_cert::request::Version,
    /// Subject name
    pub subject: Name,
    /// Subject public key info
    pub public_key: SubjectPublicKeyInfoOwned,
    /// Empty attributes - CONSTRUCTED context tag [0] with length 0
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    pub attributes: SetOfVec<Attribute>,
}

impl IntuneForLinux {
    pub fn new(
        service_endpoints: IntuneServiceEndpoints,
        #[cfg(feature = "intune_portal_vers_selection")] app_vers: Option<&str>,
        #[cfg(feature = "set_timeout")] timeout: Duration,
        #[cfg(feature = "ipvers")] ip_version: &[IpVersion],
    ) -> Result<Self, MsalError> {
        #[cfg(feature = "set_timeout")]
        let (timeout, connect_timeout) = { (timeout, min(timeout / 2, Duration::from_secs(3))) };
        #[cfg(not(feature = "set_timeout"))]
        let (timeout, connect_timeout) = (Duration::from_secs(3), Duration::from_secs(1));

        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
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

        #[cfg(feature = "ipvers")]
        {
            let has_v4 = ip_version.contains(&IpVersion::V4);
            let has_v6 = ip_version.contains(&IpVersion::V6);
            if has_v4 && !has_v6 {
                builder =
                    builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            } else if !has_v4 && has_v6 {
                builder =
                    builder.local_address(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
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

    /// Escape a string for use as an RFC4514 Distinguished Name attribute value.
    /// Special characters (,+\"\\<>;=#) and leading/trailing spaces must be escaped.
    fn escape_dn_attribute_value(value: &str) -> String {
        let mut result = String::with_capacity(value.len() * 2);
        let chars: Vec<char> = value.chars().collect();

        for (i, &ch) in chars.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chars.len() - 1;

            match ch {
                // Always escape special characters
                ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                    result.push('\\');
                    result.push(ch);
                }
                // Escape leading/trailing spaces
                ' ' if is_first || is_last => {
                    result.push('\\');
                    result.push(ch);
                }
                // Escape leading #
                '#' if is_first => {
                    result.push('\\');
                    result.push(ch);
                }
                // All other characters are fine
                _ => result.push(ch),
            }
        }

        result
    }

    /// Create a minimal PKCS#10 CSR with NO attributes for Intune enrollment.
    /// Microsoft rejects CSRs with Requested Extensions attributes.
    fn create_intune_csr(
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        device_display_name: &str,
    ) -> Result<(LoadableRS256Key, String), MsalError> {
        // Create RSA 2048-bit key in TPM
        let loadable_rs256_key = tpm
            .rs256_create(machine_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating RSA key: {:?}", e)))?;

        let rs256_key = tpm
            .rs256_load(machine_key, &loadable_rs256_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed loading RSA key: {:?}", e)))?;

        // Get public key from TPM
        let public_key = tpm
            .rs256_public(&rs256_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed getting public key: {:?}", e)))?;

        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| MsalError::CryptoFail(format!("Failed encoding public key: {:?}", e)))?;

        // Parse public key into SPKI format
        let spki = SubjectPublicKeyInfoOwned::try_from(public_key_der.as_bytes())
            .map_err(|e| MsalError::CryptoFail(format!("Failed parsing SPKI: {:?}", e)))?;

        // Build subject name: CN=device_display_name
        let subject_str = format!(
            "CN={}",
            Self::escape_dn_attribute_value(device_display_name)
        );
        let subject = Name::from_str(&subject_str)
            .map_err(|e| MsalError::CryptoFail(format!("Failed parsing subject name: {:?}", e)))?;

        // Build CertReqInfo with empty CONSTRUCTED [0] context tag
        let cert_req_info = CertReqInfoEmptyAttributes {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: spki,
            attributes: SetOfVec::new(), // Empty SET - will encode as constructed [0]
        };

        // Encode CertReqInfo to DER for signing
        let tbs_der = cert_req_info
            .to_der()
            .map_err(|e| MsalError::CryptoFail(format!("Failed encoding CertReqInfo: {:?}", e)))?;

        // Sign with TPM key
        let signature = tpm
            .rs256_sign(&rs256_key, &tbs_der)
            .map_err(|e| MsalError::TPMFail(format!("Failed signing CSR: {:?}", e)))?;

        // Convert signature to bytes (Signature can be converted to Box<[u8]>)
        let signature_box: Box<[u8]> = signature.into();
        let signature_bytes: &[u8] = &signature_box;

        // Build signature algorithm identifier (sha256WithRSAEncryption)
        let signature_algorithm = AlgorithmIdentifierOwned {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(der::asn1::AnyRef::from(der::asn1::Null).into()),
        };

        // Build the complete CSR manually
        // We use our custom structure with empty [0] context tag

        // Create a wrapper structure for the complete CSR
        #[derive(Sequence)]
        struct CertReqEmptyAttributes {
            info: CertReqInfoEmptyAttributes,
            algorithm: AlgorithmIdentifierOwned,
            signature: BitString,
        }

        let cert_req = CertReqEmptyAttributes {
            info: cert_req_info,
            algorithm: signature_algorithm,
            signature: BitString::from_bytes(signature_bytes).map_err(|e| {
                MsalError::CryptoFail(format!("Failed creating BitString: {:?}", e))
            })?,
        };

        // Convert to DER
        let csr_der = cert_req
            .to_der()
            .map_err(|e| MsalError::CryptoFail(format!("Failed encoding CSR to DER: {:?}", e)))?;

        // Convert DER to PEM using pem_rfc7468
        let csr_pem = pem_rfc7468::encode_string("CERTIFICATE REQUEST", LineEnding::LF, &csr_der)
            .map_err(|e| {
            MsalError::CryptoFail(format!("Failed converting CSR to PEM: {:?}", e))
        })?;

        Ok((loadable_rs256_key, csr_pem))
    }

    pub async fn enroll(
        &self,
        token: &UserToken,
        attrs: &EnrollAttrs,
        // device_id input is intentionally ignored for ABI compatibility with the existing enroll function, but the protocol switch to using device_display_name for the CSR subject.
        _device_id: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(LoadableMsDeviceEnrolmentKey, String), MsalError> {
        let enrollment_url = Url::parse_with_params(
            &format!(
                "{}/enroll",
                self.service_endpoints.get("LinuxEnrollmentService")?
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

        // Create the CSR using our custom function (no attributes!)
        let (loadable_rs256_key, csr_pem) =
            Self::create_intune_csr(tpm, machine_key, &attrs.device_display_name)?;

        let payload = json!({
            "CertificateSigningRequest": csr_pem,
            "AppVersion": "0.0.0",
            "DeviceName": &attrs.device_display_name,
        });

        let user_agent = format!(
            "Linux Company Portal/{}/{}",
            attrs.os_distribution, self.app_vers
        );
        let resp = send_intune_request_with_retry("enroll", || {
            self.client
                .post(enrollment_url.clone())
                .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::USER_AGENT, user_agent.as_str())
                .header(header::ACCEPT, "*/*")
                .json(&payload)
        })
        .await?;
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

            // Verify the certificate's public key matches the TPM key
            let certificate = Certificate::from_der(cert_der.as_slice()).map_err(|e| {
                MsalError::CryptoFail(format!("Failed to parse certificate: {:?}", e))
            })?;

            let rs256_key = tpm
                .rs256_load(machine_key, &loadable_rs256_key)
                .map_err(|e| MsalError::TPMFail(format!("Failed loading RSA key: {:?}", e)))?;

            let tpm_public_key = tpm
                .rs256_public(&rs256_key)
                .map_err(|e| MsalError::TPMFail(format!("Failed getting public key: {:?}", e)))?;

            let tpm_public_key_der = tpm_public_key.to_public_key_der().map_err(|e| {
                MsalError::CryptoFail(format!("Failed encoding TPM public key: {:?}", e))
            })?;

            let tpm_spki = SubjectPublicKeyInfoOwned::try_from(tpm_public_key_der.as_bytes())
                .map_err(|e| MsalError::CryptoFail(format!("Failed parsing TPM SPKI: {:?}", e)))?;

            let cert_spki = &certificate.tbs_certificate.subject_public_key_info;

            if tpm_spki != *cert_spki {
                return Err(MsalError::CryptoFail(
                    "Certificate public key does not match TPM key".to_string(),
                ));
            }

            // Store the certificate with the TPM key
            let new_loadable_cert_key = LoadableMsDeviceEnrolmentKey::Rsa2048V1 {
                loadable_rs256_key,
                x509_der: cert_der.to_vec(),
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
        let platform = IntunePlatformInfo::for_details(attrs);
        let checkin_url = checkin_url(
            self.service_endpoints.get("LinuxDeviceCheckinService")?,
            "details",
            &self.app_vers,
        )?;

        // The access token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to update device details: missing access_token".to_string(),
            )
        })?;

        let payload = details_payload(attrs, intune_device_id, &platform);

        let resp = send_intune_request_with_retry("details", || {
            details_request(
                &self.client,
                checkin_url.clone(),
                access_token,
                &platform,
                &self.app_vers,
                Uuid::new_v4(),
                &payload,
            )
        })
        .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(http_status_error("details", resp).await)
        }
    }

    pub async fn status(
        &self,
        token: &UserToken,
        payload: IntuneStatus,
    ) -> Result<IntuneStatus, MsalError> {
        let platform = IntunePlatformInfo::current();
        let status_url = checkin_url(
            self.service_endpoints.get("LinuxDeviceCheckinService")?,
            "status",
            &self.app_vers,
        )?;

        // The access token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to set device status: missing access_token".to_string(),
            )
        })?;

        let resp = send_intune_request_with_retry("status", || {
            status_request(
                &self.client,
                status_url.clone(),
                access_token,
                &platform,
                &self.app_vers,
                Uuid::new_v4(),
                &payload,
            )
        })
        .await?;

        if resp.status().is_success() {
            let status_resp: IntuneStatus = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(status_resp)
        } else {
            Err(http_status_error("status", resp).await)
        }
    }

    pub async fn policies(
        &self,
        token: &UserToken,
        intune_device_id: &str,
    ) -> Result<Vec<IntunePolicy>, MsalError> {
        let platform = IntunePlatformInfo::current();
        let url = policies_url(
            self.service_endpoints.get("LinuxDeviceCheckinService")?,
            intune_device_id,
            &self.app_vers,
        )?;

        // The access_token must be for the resource 0000000a-0000-0000-c000-000000000000
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to list device policies: missing access_token".to_string(),
            )
        })?;

        let resp = send_intune_request_with_retry("policies", || {
            policies_request(
                &self.client,
                url.clone(),
                access_token,
                &platform,
                &self.app_vers,
                Uuid::new_v4(),
            )
        })
        .await?;

        if resp.status().is_success() {
            let json_resp: IntunePolicyResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp.policies)
        } else {
            Err(http_status_error("policies", resp).await)
        }
    }

    pub async fn get_compliance_info(
        &self,
        token: &UserToken,
        intune_device_id: &str,
    ) -> Result<DeviceInfo, MsalError> {
        let platform = IntunePlatformInfo::current();
        let url = device_state_url(
            self.service_endpoints.get("IWService")?,
            intune_device_id,
            &self.app_vers,
            &platform.os_version,
            std::env::consts::ARCH,
        )?;

        // The access token must be for the resource b8066b99-6e67-41be-abfa-75db1a2c8809
        let access_token = token.access_token.as_ref().ok_or_else(|| {
            MsalError::GeneralFailure(
                "Failed to check compliance: missing access_token".to_string(),
            )
        })?;

        let resp = send_intune_request_with_retry("device-state", || {
            device_state_request(
                &self.client,
                url.clone(),
                access_token,
                &platform,
                &self.app_vers,
                Uuid::new_v4(),
            )
        })
        .await?;

        if resp.status().is_success() {
            let json_resp: DeviceInfo = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp)
        } else {
            Err(http_status_error("device-state", resp).await)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        checkin_url, details_payload, details_request, device_state_query_parameters,
        device_state_request, device_state_url, intune_architecture, intune_retry_delay,
        is_retryable_intune_status, policies_request, policies_url, sanitize_http_error_body,
        select_device_state_os_version, status_request, IntunePlatformInfo, IntunePolicy,
        IntunePolicyResponse, IntuneStatus, PolicySetting, MAX_HTTP_ERROR_BODY_LEN,
    };
    use crate::EnrollAttrs;
    use reqwest::{header, StatusCode};
    use serde_json::json;
    use std::time::Duration;
    use uuid::{Uuid, Version};

    fn test_platform() -> IntunePlatformInfo {
        IntunePlatformInfo {
            os_distribution: "ubuntu".to_string(),
            os_version: "24.04".to_string(),
        }
    }

    fn test_attrs() -> Result<EnrollAttrs, String> {
        EnrollAttrs::new(
            "example.test".to_string(),
            Some("dmulder-Standard-PC-i440FX-PIIX-1996".to_string()),
            Some("Linux".to_string()),
            Some(0),
            Some("Ubuntu 24.04.3 LTS 24.04".to_string()),
        )
        .map_err(|e| format!("{:?}", e))
    }

    fn assert_captured_compliance_headers(
        request: &reqwest::Request,
        expected_user_agent: &str,
        expected_request_id: Uuid,
    ) -> Result<(), String> {
        assert_eq!(
            request.headers().get(header::ACCEPT),
            Some(&header::HeaderValue::from_static("*/*"))
        );
        let user_agent = request
            .headers()
            .get(header::USER_AGENT)
            .ok_or_else(|| "missing user-agent header".to_string())?;
        assert_eq!(user_agent, expected_user_agent);
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .ok_or_else(|| "missing authorization header".to_string())?;
        assert_eq!(authorization, "Bearer secret");
        let request_id = request
            .headers()
            .get("client-request-id")
            .ok_or_else(|| "missing client-request-id header".to_string())?;
        assert_eq!(request_id, expected_request_id.to_string().as_str());
        let request_id = request_id.to_str().map_err(|e| e.to_string())?;
        assert_eq!(
            Uuid::parse_str(request_id)
                .map_err(|e| e.to_string())?
                .get_version(),
            Some(Version::Random)
        );
        Ok(())
    }

    #[test]
    fn intune_architecture_normalizes_known_values() {
        assert_eq!(intune_architecture("x86_64"), "X64");
        assert_eq!(intune_architecture("aarch64"), "ARM64");
        assert_eq!(intune_architecture("x86"), "X86");
        assert_eq!(intune_architecture("i686"), "X86");
        assert_eq!(intune_architecture("riscv64"), "riscv64");
    }

    #[test]
    fn intune_retry_status_is_limited_to_reported_protocol_failures() {
        assert!(is_retryable_intune_status(StatusCode::NOT_FOUND));
        assert!(is_retryable_intune_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));

        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(!is_retryable_intune_status(status));
        }
    }

    #[test]
    fn intune_retry_delay_uses_fixed_three_retry_budget() {
        assert_eq!(
            intune_retry_delay(StatusCode::INTERNAL_SERVER_ERROR, 0),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            intune_retry_delay(StatusCode::INTERNAL_SERVER_ERROR, 1),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            intune_retry_delay(StatusCode::INTERNAL_SERVER_ERROR, 2),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            intune_retry_delay(StatusCode::INTERNAL_SERVER_ERROR, 3),
            None
        );
        assert_eq!(intune_retry_delay(StatusCode::FORBIDDEN, 0), None);
    }

    #[test]
    fn device_state_query_contains_platform_metadata() {
        assert_eq!(
            device_state_query_parameters("1.2607.4", "24.04", "x86_64"),
            [
                ("api-version", "16.4".to_string()),
                ("ssp", "LinuxCP".to_string()),
                ("ssp-version", "1.2607.4".to_string()),
                ("os", "Linux".to_string()),
                ("os-version", "24.04".to_string()),
                ("os-sub", "None".to_string()),
                ("arch", "X64".to_string()),
                ("mgmt-agent", "mdm".to_string()),
            ]
        );
    }

    #[test]
    fn device_state_os_version_uses_fail_soft_fallbacks() {
        assert_eq!(
            select_device_state_os_version(Some(" 24.04 \n"), Some("6.8.0-79-generic")),
            "24.04"
        );
        assert_eq!(
            select_device_state_os_version(Some("  "), Some(" 6.8.0-79-generic\n")),
            "6.8.0-79-generic"
        );
        assert_eq!(
            select_device_state_os_version(None, Some("6.8.0-79-generic")),
            "6.8.0-79-generic"
        );
        assert_eq!(select_device_state_os_version(Some(""), Some("\n")), "0");
        assert_eq!(select_device_state_os_version(None, None), "0");
    }

    #[test]
    fn device_state_request_matches_wire_format() -> Result<(), String> {
        let platform = test_platform();
        let request_id =
            Uuid::parse_str("fe37a924-cf3c-452d-a261-42f419b7abc8").map_err(|e| e.to_string())?;
        let url = device_state_url(
            "https://example.test/StatelessIWService",
            "33ca45ed-7b2a-42d1-b96d-ab07aecf330a",
            "1.2607.4",
            "24.04",
            "x86_64",
        )
        .map_err(|e| format!("{:?}", e))?;
        let request = device_state_request(
            &reqwest::Client::new(),
            url,
            "secret",
            &platform,
            "1.2607.4",
            request_id,
        )
        .build()
        .map_err(|e| format!("{:?}", e))?;
        let query: std::collections::BTreeMap<_, _> =
            request.url().query_pairs().into_owned().collect();

        assert_eq!(request.method(), reqwest::Method::GET);
        assert_captured_compliance_headers(
            &request,
            "Linux Company Portal/ubuntu 24.04/1.2607.4",
            request_id,
        )?;
        assert!(request.headers().get(header::CONTENT_TYPE).is_none());
        assert_eq!(query.get("api-version").map(String::as_str), Some("16.4"));
        assert_eq!(query.get("ssp").map(String::as_str), Some("LinuxCP"));
        assert_eq!(
            query.get("ssp-version").map(String::as_str),
            Some("1.2607.4")
        );
        assert_eq!(query.get("os").map(String::as_str), Some("Linux"));
        assert_eq!(query.get("os-version").map(String::as_str), Some("24.04"));
        assert_eq!(query.get("os-sub").map(String::as_str), Some("None"));
        assert_eq!(query.get("arch").map(String::as_str), Some("X64"));
        assert_eq!(query.get("mgmt-agent").map(String::as_str), Some("mdm"));
        assert_eq!(query.len(), 8);

        Ok(())
    }

    #[test]
    fn details_request_matches_captured_wire_format() -> Result<(), String> {
        let platform = test_platform();
        let attrs = test_attrs()?;
        let request_id =
            Uuid::parse_str("f656a2df-cd00-44b2-8eea-5caf2a7ab8a3").map_err(|e| e.to_string())?;
        let url = checkin_url(
            "https://example.test/LinuxDeviceCheckinService",
            "details",
            "1.2604.19",
        )
        .map_err(|e| format!("{:?}", e))?;
        let payload = details_payload(&attrs, "33ca45ed-7b2a-42d1-b96d-ab07aecf330a", &platform);
        let request = details_request(
            &reqwest::Client::new(),
            url,
            "secret",
            &platform,
            "1.2604.19",
            request_id,
            &payload,
        )
        .build()
        .map_err(|e| format!("{:?}", e))?;
        let query: std::collections::BTreeMap<_, _> =
            request.url().query_pairs().into_owned().collect();

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_captured_compliance_headers(
            &request,
            "Linux Company Portal/ubuntu 24.04/1.2604.19",
            request_id,
        )?;
        assert_eq!(
            request.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(request.url().path(), "/LinuxDeviceCheckinService/details");
        assert_eq!(query.get("api-version").map(String::as_str), Some("1.0"));
        assert_eq!(
            query.get("client-version").map(String::as_str),
            Some("1.2604.19")
        );
        assert_eq!(payload["DeviceId"], "33ca45ed-7b2a-42d1-b96d-ab07aecf330a");
        assert_eq!(
            payload["DeviceName"],
            "dmulder-Standard-PC-i440FX-PIIX-1996"
        );
        assert_eq!(payload["OSDistribution"], "ubuntu");
        assert_eq!(payload["OSVersion"], "24.04");

        Ok(())
    }

    #[test]
    fn policies_request_matches_captured_wire_format() -> Result<(), String> {
        let platform = test_platform();
        let request_id =
            Uuid::parse_str("00142a4b-8fe8-49b8-af77-da34f9ffa05f").map_err(|e| e.to_string())?;
        let url = policies_url(
            "https://example.test/LinuxDeviceCheckinService",
            "33ca45ed-7b2a-42d1-b96d-ab07aecf330a",
            "1.2604.19",
        )
        .map_err(|e| format!("{:?}", e))?;
        let request = policies_request(
            &reqwest::Client::new(),
            url,
            "secret",
            &platform,
            "1.2604.19",
            request_id,
        )
        .build()
        .map_err(|e| format!("{:?}", e))?;
        let query: std::collections::BTreeMap<_, _> =
            request.url().query_pairs().into_owned().collect();

        assert_eq!(request.method(), reqwest::Method::GET);
        assert_captured_compliance_headers(
            &request,
            "Linux Company Portal/ubuntu 24.04/1.2604.19",
            request_id,
        )?;
        assert!(request.headers().get(header::CONTENT_TYPE).is_none());
        assert_eq!(
            request.url().path(),
            "/LinuxDeviceCheckinService/policies/33ca45ed-7b2a-42d1-b96d-ab07aecf330a"
        );
        assert_eq!(query.get("api-version").map(String::as_str), Some("1.0"));
        assert_eq!(
            query.get("client-version").map(String::as_str),
            Some("1.2604.19")
        );

        Ok(())
    }

    #[test]
    fn status_request_matches_captured_empty_payload() -> Result<(), String> {
        let platform = test_platform();
        let request_id =
            Uuid::parse_str("c6e88cf1-056d-4f61-8767-5dbaabb2b4b7").map_err(|e| e.to_string())?;
        let url = checkin_url(
            "https://example.test/LinuxDeviceCheckinService",
            "status",
            "1.2604.19",
        )
        .map_err(|e| format!("{:?}", e))?;
        let payload = IntuneStatus {
            device_id: Some("33ca45ed-7b2a-42d1-b96d-ab07aecf330a".to_string()),
            policy_statuses: Vec::new(),
        };
        let payload_json = serde_json::to_value(&payload).map_err(|e| e.to_string())?;
        let request = status_request(
            &reqwest::Client::new(),
            url,
            "secret",
            &platform,
            "1.2604.19",
            request_id,
            &payload,
        )
        .build()
        .map_err(|e| format!("{:?}", e))?;

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_captured_compliance_headers(
            &request,
            "Linux Company Portal/ubuntu 24.04/1.2604.19",
            request_id,
        )?;
        assert_eq!(
            request.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            payload_json,
            json!({
                "DeviceId": "33ca45ed-7b2a-42d1-b96d-ab07aecf330a",
                "PolicyStatuses": []
            })
        );

        Ok(())
    }

    #[test]
    fn status_response_accepts_pascal_case_and_camel_case() -> Result<(), String> {
        let status: IntuneStatus =
            serde_json::from_str(r#"{"policyStatuses":[]}"#).map_err(|e| e.to_string())?;
        assert!(status.device_id.is_none());
        assert!(status.policy_statuses.is_empty());

        let status: IntuneStatus =
            serde_json::from_str(r#"{"PolicyStatuses":[]}"#).map_err(|e| e.to_string())?;
        assert!(status.policy_statuses.is_empty());

        let status: IntuneStatus = serde_json::from_str(
            r#"{"policyStatuses":[{"policyId":"policy","lastStatusDateTime":"2026-08-27T12:44:19+00:00","details":[{"ruleId":"rule","settingDefinitionItemId":"setting","expectedValue":"expected","actualValue":"actual","errorType":0,"errorCode":0,"newComplianceState":"Compliant","oldComplianceState":"Unknown"}]}]}"#,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(status.policy_statuses[0].policy_id, "policy");
        assert_eq!(status.policy_statuses[0].details[0].rule_id, "rule");

        let status: IntuneStatus = serde_json::from_str(
            r#"{"PolicyStatuses":[{"PolicyId":"policy","LastStatusDateTime":"2026-08-27T12:44:19+00:00","Details":[{"RuleId":"rule","SettingDefinitionItemId":"setting","ExpectedValue":"expected","ActualValue":"actual","ErrorType":0,"ErrorCode":0,"NewComplianceState":"Compliant","OldComplianceState":"Unknown"}]}]}"#,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(status.policy_statuses[0].policy_id, "policy");
        assert_eq!(status.policy_statuses[0].details[0].rule_id, "rule");

        Ok(())
    }

    #[test]
    fn policy_response_accepts_pascal_case_and_camel_case() -> Result<(), String> {
        for response in [
            r#"{"policies":[{"accountId":"account","description":"description","policyId":"policy","policySettings":[{"cspPath":"path","cspPathId":"path-id","ruleId":"rule","settingDefinitionItemId":"setting","value":"value"}],"policyType":"Configuration","version":1}]}"#,
            r#"{"Policies":[{"AccountId":"account","Description":"description","PolicyId":"policy","PolicySettings":[{"CspPath":"path","CspPathId":"path-id","RuleId":"rule","SettingDefinitionItemId":"setting","Value":"value"}],"PolicyType":"Configuration","Version":1}]}"#,
        ] {
            let policies: IntunePolicyResponse =
                serde_json::from_str(response).map_err(|e| e.to_string())?;
            assert_eq!(policies.policies[0].policy_id, "policy");
            assert_eq!(policies.policies[0].policy_settings[0].rule_id, "rule");
        }

        Ok(())
    }

    #[test]
    fn generated_policy_details_include_captured_zero_error_fields() -> Result<(), String> {
        let policies = vec![IntunePolicy {
            account_id: "account".to_string(),
            description: "".to_string(),
            policy_id: "policy".to_string(),
            policy_settings: vec![PolicySetting {
                csp_path: "com.microsoft.manage.LinuxMdm/CustomConfig/Script".to_string(),
                csp_path_id: "csp-path-id".to_string(),
                rule_id: "rule".to_string(),
                setting_definition_item_id: "linux_customconfig_script".to_string(),
                value: "expected".to_string(),
            }],
            policy_type: "Configuration".to_string(),
            version: 1,
        }];
        let status = IntuneStatus::from(policies);
        let detail = &status.policy_statuses[0].details[0];
        assert_eq!(detail.error_code, Some(0));
        assert_eq!(detail.error_type, Some(0));

        let serialized = serde_json::to_value(status).map_err(|e| e.to_string())?;
        assert_eq!(
            serialized["PolicyStatuses"][0]["Details"][0]["ErrorCode"],
            json!(0)
        );
        assert_eq!(
            serialized["PolicyStatuses"][0]["Details"][0]["ErrorType"],
            json!(0)
        );

        Ok(())
    }

    #[test]
    fn http_error_body_is_escaped_and_bounded() {
        let body = format!(
            "line one\nline two\0{}",
            "x".repeat(MAX_HTTP_ERROR_BODY_LEN)
        );
        let sanitized = sanitize_http_error_body(&body);

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\0'));
        assert!(sanitized.contains("\\n"));
        assert!(sanitized.contains("\\u{0}"));
        assert_eq!(sanitized.len(), MAX_HTTP_ERROR_BODY_LEN);
    }
}
