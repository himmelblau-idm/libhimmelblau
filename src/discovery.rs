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

use std::fs;
use std::io::Read;

use crate::error::MsalError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use os_release::OsRelease;
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::to_string_pretty;
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DRS_CLIENT_NAME_HEADER_FIELD: &str = "ocp-adrs-client-name";
pub const DRS_CLIENT_VERSION_HEADER_FIELD: &str = "ocp-adrs-client-version";
pub const DISCOVERY_URL: &str = "https://enterpriseregistration.windows.net";
const DRS_PROTOCOL_VERSION: &str = "1.9";

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Certificate {
    #[serde(rename = "RawBody")]
    raw_body: String,
}

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DRSResponse {
    #[serde(rename = "Certificate")]
    certificate: Certificate,
}

#[cfg(feature = "broker")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct BcryptRsaKeyBlob {
    bit_length: u32,
    exponent: Vec<u8>,
    modulus: Vec<u8>,
}

#[cfg(feature = "broker")]
impl BcryptRsaKeyBlob {
    pub(crate) fn new(bit_length: u32, exponent: &[u8], modulus: &[u8]) -> Self {
        BcryptRsaKeyBlob {
            bit_length,
            exponent: exponent.to_vec(),
            modulus: modulus.to_vec(),
        }
    }
}

#[cfg(feature = "broker")]
impl TryInto<Vec<u8>> for BcryptRsaKeyBlob {
    type Error = MsalError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut cng_blob = b"RSA1".to_vec(); // Magic
        cng_blob.extend_from_slice(&self.bit_length.to_le_bytes()); // BitLength
        let exponent_len: u32 = self.exponent.len().try_into().map_err(|e| {
            MsalError::GeneralFailure(format!("Exponent len into u32 failed: {:?}", e))
        })?;
        cng_blob.extend_from_slice(&exponent_len.to_le_bytes()); // cbPublicExpLength
        let modulus_len: u32 = self.modulus.len().try_into().map_err(|e| {
            MsalError::GeneralFailure(format!("Modulus len into u32 failed: {:?}", e))
        })?;
        cng_blob.extend_from_slice(&modulus_len.to_le_bytes()); // cbModulusLength

        // MS reserves spots for P and Q lengths, but doesn't permit P and Q in
        // the blob itself. Requests will be rejected if P and Q are specified.
        let prime1_len: u32 = 0;
        cng_blob.extend_from_slice(&prime1_len.to_le_bytes()); // cbPrime1Length
        let prime2_len: u32 = 0;
        cng_blob.extend_from_slice(&prime2_len.to_le_bytes()); // cbPrime2Length

        cng_blob.extend_from_slice(self.exponent.as_slice()); // cbPublicExp
        cng_blob.extend_from_slice(self.modulus.as_slice()); // cbModulus
        Ok(cng_blob)
    }
}

#[derive(Debug, Deserialize)]
pub struct ServicesService {
    #[serde(rename = "ServicesEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceRegistrationService {
    #[serde(rename = "RegistrationEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "RegistrationResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuth2 {
    #[serde(rename = "AuthCodeEndpoint")]
    pub auth_code_endpoint: Option<String>,
    #[serde(rename = "TokenEndpoint")]
    pub token_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationService {
    #[serde(rename = "OAuth2")]
    pub oauth2: Option<OAuth2>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityProviderService {
    #[serde(rename = "Federated")]
    pub federated: Option<bool>,
    #[serde(rename = "PassiveAuthEndpoint")]
    pub passive_auth_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceJoinService {
    #[serde(rename = "JoinEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "JoinResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KeyProvisioningService {
    #[serde(rename = "KeyProvisionEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "KeyProvisionResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthNService {
    #[serde(rename = "WebAuthNEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "WebAuthNResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceManagementService {
    #[serde(rename = "DeviceManagementEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "DeviceManagementResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MsaProviderData {
    #[serde(rename = "SiteId")]
    pub site_id: Option<String>,
    #[serde(rename = "SiteUrl")]
    pub site_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PrecreateService {
    #[serde(rename = "PrecreateEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "PrecreateResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TenantInfo {
    #[serde(rename = "TenantId")]
    pub tenant_id: Option<String>,
    #[serde(rename = "TenantName")]
    pub tenant_name: Option<String>,
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AzureRbacService {
    #[serde(rename = "RbacPolicyEndpoint")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BPLService {
    #[serde(rename = "BPLServiceEndpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "BPLResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
    #[serde(rename = "BPLProxyServicePrincipalId")]
    pub service_principal_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceJoinResourceService {
    #[serde(rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NonceService {
    #[serde(rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(rename = "ResourceId")]
    pub resource_id: Option<String>,
    #[serde(rename = "ServiceVersion")]
    pub service_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NonceResp {
    #[serde(rename = "Value")]
    value: String,
}

fn get_manufacturer() -> Option<String> {
    let path = "/sys/class/dmi/id/sys_vendor";

    let mut file = fs::File::open(path).ok()?;
    let mut manufacturer = String::new();
    file.read_to_string(&mut manufacturer).ok()?;

    Some(manufacturer.trim().to_string())
}

#[cfg(feature = "broker")]
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollAttrs {
    pub(crate) device_display_name: String,
    pub(crate) device_type: String,
    join_type: u32,
    pub(crate) os_version: String,
    pub(crate) target_domain: String,
    pub(crate) os_distribution: String,
    pub(crate) manufacturer: String,
}

#[cfg(feature = "broker")]
impl EnrollAttrs {
    /// Initialize attributes for device enrollment
    ///
    /// # Arguments
    ///
    /// * `target_domain` - The domain to be enrolled in.
    ///
    /// * `device_display_name` - An optional chosen display name for the
    ///   enrolled device. Defaults to the system hostname.
    ///
    /// * `device_type` - An optional device type. Defaults to 'Linux'. This
    ///   effects which Intune policies are distributed to the client.
    ///
    /// * `join_type` - An optional join type. Defaults to 0. Possible values
    ///   are:
    ///     - 0: Azure AD join.
    ///     - 4: Azure AD register only.
    ///     - 6: Azure AD hybrid join.
    ///     - 8: Azure AD join.
    ///
    /// * `os_version` - An optional OS version. Defaults to the contents of
    ///   /etc/os-release.
    ///
    /// * Success: A new EnrollAttrs for device enrollment.
    /// * Failure: An MsalError, indicating the failure.
    pub fn new(
        target_domain: String,
        device_display_name: Option<String>,
        device_type: Option<String>,
        join_type: Option<u32>,
        os_version: Option<String>,
    ) -> Result<Self, MsalError> {
        let os_release =
            OsRelease::new().map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
        let os_distribution = os_release.name;

        let device_display_name_int = match device_display_name {
            Some(device_display_name) => device_display_name,
            None => match hostname::get()
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
                .to_str()
            {
                Some(host) => String::from(host),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "Failed to get machine hostname for enrollment".to_string(),
                    ))
                }
            },
        };
        let device_type_int = match device_type {
            Some(device_type) => device_type,
            None => "Linux".to_string(),
        };
        let join_type_int = join_type.unwrap_or(0);
        let os_version_int = match os_version {
            Some(os_version) => os_version,
            None => {
                format!("{} {}", os_release.pretty_name, os_release.version_id)
            }
        };
        Ok(EnrollAttrs {
            device_display_name: device_display_name_int,
            device_type: device_type_int,
            join_type: join_type_int,
            os_version: os_version_int,
            target_domain,
            os_distribution,
            manufacturer: get_manufacturer().unwrap_or_default(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct Services {
    #[serde(skip_deserializing)]
    client: Client,
    #[serde(rename = "ServicesService")]
    pub discovery_service: Option<ServicesService>,
    #[serde(rename = "DeviceRegistrationService")]
    pub device_registration_service: Option<DeviceRegistrationService>,
    #[serde(rename = "AuthenticationService")]
    pub authentication_service: Option<AuthenticationService>,
    #[serde(rename = "IdentityProviderService")]
    pub identity_provider_service: Option<IdentityProviderService>,
    #[serde(rename = "DeviceJoinService")]
    pub device_join_service: Option<DeviceJoinService>,
    #[serde(rename = "KeyProvisioningService")]
    pub key_provisioning_service: Option<KeyProvisioningService>,
    #[serde(rename = "WebAuthNService")]
    pub web_auth_n_service: Option<WebAuthNService>,
    #[serde(rename = "DeviceManagementService")]
    pub device_management_service: Option<DeviceManagementService>,
    #[serde(rename = "MsaProviderData")]
    pub msa_provider_data: Option<MsaProviderData>,
    #[serde(rename = "PrecreateService")]
    pub precreate_service: Option<PrecreateService>,
    #[serde(rename = "TenantInfo")]
    pub tenant_info: Option<TenantInfo>,
    #[serde(rename = "AzureRbacService")]
    pub azure_rbac_service: Option<AzureRbacService>,
    #[serde(rename = "BPLService")]
    pub bpl_service: Option<BPLService>,
    #[serde(rename = "DeviceJoinResourceService")]
    pub device_join_resource_service: Option<DeviceJoinResourceService>,
    #[serde(rename = "NonceService")]
    nonce_service: Option<NonceService>,
}

impl Services {
    pub async fn new(access_token: &str, domain_name: &str) -> Result<Self, MsalError> {
        let url = Url::parse_with_params(
            &format!("{}/{}/Discover", DISCOVERY_URL, domain_name),
            &[("api-version", DRS_PROTOCOL_VERSION), ("managed", "True")],
        )
        .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
            .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
            .header(
                "User-Agent",
                format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            )
            .header(header::ACCEPT, "application/json, text/plain, */*")
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let mut json_resp: Services = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            json_resp.client = client;
            Ok(json_resp)
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    pub async fn request_nonce(
        &self,
        tenant_id: &str,
        access_token: &str,
    ) -> Result<String, MsalError> {
        let fallback_endpoint = format!("{}/EnrollmentServer/nonce/{}/", DISCOVERY_URL, tenant_id);
        let url = match &self.nonce_service {
            Some(nonce_service) => {
                let endpoint = match &nonce_service.endpoint {
                    Some(endpoint) => endpoint,
                    None => &fallback_endpoint,
                };
                let service_version = match &nonce_service.service_version {
                    Some(service_version) => service_version,
                    None => "1.0",
                };
                Url::parse_with_params(endpoint, &[("api-version", &service_version)])
                    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?
            }
            None => Url::parse_with_params(&fallback_endpoint, &[("api-version", "1.0")])
                .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?,
        };

        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
        if resp.status().is_success() {
            let json_resp: NonceResp = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp.value)
        } else {
            Err(MsalError::RequestFailed(format!("{}", resp.status())))
        }
    }

    #[cfg(feature = "broker")]
    pub async fn enroll_device(
        &self,
        access_token: &str,
        attrs: EnrollAttrs,
        transport_key: &Rsa<Public>,
        csr_der: &Vec<u8>,
    ) -> Result<(X509, String), MsalError> {
        let fallback_endpoint = format!("{}/EnrollmentServer/device/", DISCOVERY_URL);
        let (join_endpoint, service_version) = match &self.device_join_service {
            Some(device_join_service) => {
                let join_endpoint = match &device_join_service.endpoint {
                    Some(join_endpoint) => join_endpoint,
                    None => &fallback_endpoint,
                };
                let service_version = match &device_join_service.service_version {
                    Some(service_version) => service_version,
                    None => "2.0",
                };
                (join_endpoint, service_version)
            }
            None => (&fallback_endpoint, "2.0"),
        };

        let url = Url::parse_with_params(join_endpoint, &[("api-version", service_version)])
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let transport_key_blob: Vec<u8> = BcryptRsaKeyBlob::new(
            2048,
            &transport_key.e().to_vec(),
            &transport_key.n().to_vec(),
        )
        .try_into()?;

        let payload = json!({
            "CertificateRequest": {
                "Type": "pkcs10",
                "Data": STANDARD.encode(csr_der)
            },
            "DeviceDisplayName": attrs.device_display_name,
            "DeviceType": attrs.device_type,
            "JoinType": attrs.join_type,
            "OSVersion": attrs.os_version,
            "TargetDomain": attrs.target_domain,
            "TransportKey": STANDARD.encode(transport_key_blob),
            "Attributes": {
                "ReuseDevice": "true",
                "ReturnClientSid": "true"
            }
        });
        if let Ok(pretty) = to_string_pretty(&payload) {
            debug!("POST {}: {}", url, pretty);
        }
        let resp = self
            .client
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
            Ok((cert, device_id.to_string()))
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    pub fn key_provisioning_resource_id(&self) -> String {
        match &self.key_provisioning_service {
            Some(key_provisioning_service) => match &key_provisioning_service.resource_id {
                Some(resource_id) => resource_id.clone(),
                None => "urn:ms-drs:enterpriseregistration.windows.net".to_string(),
            },
            None => "urn:ms-drs:enterpriseregistration.windows.net".to_string(),
        }
    }

    pub async fn provision_key(
        &self,
        access_token: &str,
        pub_key: &Rsa<Public>,
    ) -> Result<(), MsalError> {
        let fallback_endpoint = format!("{}/EnrollmentServer/key/", DISCOVERY_URL);
        let (endpoint, service_version) = match &self.key_provisioning_service {
            Some(key_provisioning_service) => {
                let endpoint = match &key_provisioning_service.endpoint {
                    Some(endpoint) => endpoint,
                    None => &fallback_endpoint,
                };
                let service_version = match &key_provisioning_service.service_version {
                    Some(service_version) => service_version,
                    None => "1.0",
                };
                (endpoint, service_version)
            }
            None => (&fallback_endpoint, "1.0"),
        };

        let key_blob: Vec<u8> =
            BcryptRsaKeyBlob::new(2048, &pub_key.e().to_vec(), &pub_key.n().to_vec()).try_into()?;

        // [MS-KPP] 3.1.5.1.1.1 Request Body
        // Register the public key
        let payload = json!({
            "kngc": STANDARD.encode(key_blob),
        });
        let url = Url::parse_with_params(endpoint, &[("api-version", service_version)])
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        debug!("POST {}: {{ \"kngc\": <PUBLIC KEY> }}", url);

        let resp = self
            .client
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::USER_AGENT,
                format!("Dsreg/10.0 ({})", env!("CARGO_PKG_NAME")),
            )
            .header(header::ACCEPT, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MsalError::GeneralFailure(
                "Failed registering Key".to_string(),
            ))
        }
    }
}
