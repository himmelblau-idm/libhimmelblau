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

use crate::error::MsalError;
#[cfg(feature = "proxyable")]
use reqwest::Proxy;
use reqwest::{header, Client, StatusCode, Url};
use serde::de::{DeserializeOwned, Error};
use serde::Deserialize;
use serde_json::{json, to_string_pretty};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::debug;

#[cfg(feature = "ipvers")]
use crate::auth::IpVersion;
#[cfg(feature = "set_timeout")]
use std::cmp::min;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

#[derive(Debug)]
pub struct DirectoryObject {
    pub data_type: String,
    pub id: String,
    pub description: Option<String>,
    pub display_name: Option<String>,
    pub security_identifier: Option<String>,
    pub extension_attrs: HashMap<String, String>,
}

impl<'de> Deserialize<'de> for DirectoryObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut map = Map::<String, Value>::deserialize(deserializer)?;

        let data_type = map
            .remove("@odata.type")
            .ok_or_else(|| D::Error::missing_field("@odata.type"))?;
        let data_type: String = serde_json::from_value(data_type).map_err(D::Error::custom)?;

        let id = map
            .remove("id")
            .ok_or_else(|| D::Error::missing_field("id"))?;
        let id: String = serde_json::from_value(id).map_err(D::Error::custom)?;

        let description: Option<String> = map.remove("description").map_or(Ok(None), |v| {
            serde_json::from_value(v).map_err(D::Error::custom)
        })?;
        let display_name: Option<String> = map.remove("displayName").map_or(Ok(None), |v| {
            serde_json::from_value(v).map_err(D::Error::custom)
        })?;
        let security_identifier: Option<String> =
            map.remove("securityIdentifier").map_or(Ok(None), |v| {
                serde_json::from_value(v).map_err(D::Error::custom)
            })?;

        let mut extension_attrs = HashMap::new();
        for (key, value) in map {
            if key.starts_with("extension_") {
                let s = if let Value::String(s) = value {
                    s
                } else {
                    value.to_string()
                };
                let short_key = key.splitn(3, '_').nth(2).unwrap_or(&key).to_string();
                extension_attrs.insert(short_key, s);
            }
        }

        Ok(DirectoryObject {
            data_type,
            id,
            description,
            display_name,
            security_identifier,
            extension_attrs,
        })
    }
}

#[derive(Deserialize)]
struct GraphPage<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    #[serde(rename = "userPrincipalName")]
    pub upn: String,
    #[serde(rename = "onPremisesSamAccountName")]
    pub on_premises_sam_account_name: Option<String>,
    pub id: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Result of an exact Graph user lookup by UPN or object ID.
///
/// A lookup failure is never evidence that the requested identity is absent.
#[derive(Debug)]
pub enum ExactUserLookup {
    Found(UserObject),
    /// Graph returned HTTP 404 with its structured Request_ResourceNotFound error.
    NotFound,
}

#[derive(Deserialize)]
struct GraphErrorResponse {
    error: GraphError,
}

#[derive(Deserialize)]
struct GraphError {
    code: String,
    // Validate the Graph error envelope, but never match human-readable text.
    #[serde(rename = "message")]
    _message: String,
}

#[derive(Debug, Deserialize)]
pub struct GroupObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    pub id: String,
    pub gid: Option<u32>,
}

#[derive(Deserialize)]
struct IntuneServiceEndpoint {
    #[serde(rename = "providerName")]
    provider_name: String,
    uri: String,
}

#[derive(Deserialize)]
pub struct IntuneServiceEndpoints {
    value: Vec<IntuneServiceEndpoint>,
}

impl IntuneServiceEndpoints {
    pub fn get(&self, provider_name: &str) -> Result<&str, MsalError> {
        self.value
            .iter()
            .find(|ep| ep.provider_name == provider_name)
            .map(|ep| ep.uri.as_str())
            .ok_or_else(|| MsalError::Missing(provider_name.to_string()))
    }
}

pub struct Graph {
    client: Client,
    exact_client: Client,
    odc_provider: String,
    domain: String,
    federation_provider: RwLock<Option<FederationProvider>>,
}

async fn request_federation_provider(
    client: &Client,
    odc_provider: &str,
    domain: &str,
) -> Result<FederationProvider, MsalError> {
    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        &[("domain", domain)],
    )
    .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| MsalError::request_failed(&e))?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp
            .json()
            .await
            .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
        debug!("Discovered: {:?}", json_resp);
        Ok(json_resp)
    } else {
        Err(MsalError::GeneralFailure(format!(
            "Federation Provider request failed: {}",
            resp.status(),
        )))
    }
}

macro_rules! federation_provider_or_none {
    ($client:expr, $odc_provider:expr, $domain:expr) => {{
        match request_federation_provider(&$client, $odc_provider, $domain).await {
            Ok(resp) => Some(resp),
            Err(e) => {
                debug!("{:?}", e);
                None
            }
        }
    }};
}

macro_rules! federation_provider_fetch {
    ($graph:ident, $val:ident) => {{
        {
            let mut federation_provider = $graph.federation_provider.write().await;
            if federation_provider.is_none() {
                *federation_provider = federation_provider_or_none!(
                    $graph.client,
                    &$graph.odc_provider,
                    &$graph.domain
                );
            }
        }
        // This nested scope forces the drop of the federation_provider write
        // lock, otherwise we deadlock when we request a read lock next.

        match &*$graph.federation_provider.read().await {
            Some(federation_provider) => Ok(federation_provider.$val.clone()),
            None => Err(MsalError::GeneralFailure(
                "federation provider not set".to_string(),
            )),
        }
    }};
}

impl Graph {
    pub async fn new(
        odc_provider: &str,
        domain: &str,
        authority_host: Option<&str>,
        tenant_id: Option<&str>,
        graph_url: Option<&str>,
        #[cfg(feature = "set_timeout")] timeout: Duration,
        #[cfg(feature = "ipvers")] ip_version: &[IpVersion],
    ) -> Result<Self, MsalError> {
        #[cfg(feature = "set_timeout")]
        let (timeout, connect_timeout) = { (timeout, min(timeout / 2, Duration::from_secs(3))) };
        #[cfg(not(feature = "set_timeout"))]
        let (timeout, connect_timeout) = (Duration::from_secs(3), Duration::from_secs(1));

        let build_client = |redirect_policy| {
            #[allow(unused_mut)]
            let mut builder = reqwest::Client::builder()
                .connect_timeout(connect_timeout)
                .timeout(timeout)
                .cookie_store(true)
                .redirect(redirect_policy);

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

            builder
                .build()
                .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))
        };
        let client = build_client(reqwest::redirect::Policy::default())?;
        // Exact identity proofs must describe the requested endpoint, never a
        // redirect target. Keep the other connection settings identical.
        let exact_client = build_client(reqwest::redirect::Policy::none())?;

        let federation_provider = if let Some(authority_host) = authority_host {
            if let Some(tenant_id) = tenant_id {
                if let Some(graph_url) = graph_url {
                    Some(FederationProvider {
                        authority_host: authority_host.to_string(),
                        tenant_id: tenant_id.to_string(),
                        graph: graph_url.to_string(),
                    })
                } else {
                    federation_provider_or_none!(client, odc_provider, domain)
                }
            } else {
                federation_provider_or_none!(client, odc_provider, domain)
            }
        } else {
            federation_provider_or_none!(client, odc_provider, domain)
        };

        Ok(Graph {
            client,
            exact_client,
            odc_provider: odc_provider.to_string(),
            domain: domain.to_string(),
            federation_provider: RwLock::new(federation_provider),
        })
    }

    pub async fn authority_host(&self) -> Result<String, MsalError> {
        federation_provider_fetch!(self, authority_host)
    }

    pub async fn tenant_id(&self) -> Result<String, MsalError> {
        federation_provider_fetch!(self, tenant_id)
    }

    pub async fn graph_url(&self) -> Result<String, MsalError> {
        federation_provider_fetch!(self, graph)
    }

    pub async fn request_user(
        &self,
        access_token: &str,
        upn: &str,
    ) -> Result<UserObject, MsalError> {
        // onPremisesSamAccountName is not part of Graph's default user
        // response. Select it along with every required UserObject property,
        // so a successful response can distinguish an absent SAM name from a
        // failed request.
        let mut url = Url::parse(&format!(
            "{}/v1.0/users/{}",
            self.graph_url().await?.trim_end_matches('/'),
            percent_encoding::utf8_percent_encode(upn, percent_encoding::NON_ALPHANUMERIC)
        ))
        .map_err(|e| MsalError::URLFormatFailed(e.to_string()))?;
        url.query_pairs_mut().append_pair(
            "$select",
            "id,displayName,userPrincipalName,onPremisesSamAccountName",
        );
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: UserObject = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    /// Look up one user by UPN or object ID without following redirects.
    ///
    /// The returned user's UPN is the value from Graph, not the lookup input.
    /// Only HTTP 404 with a valid Graph `Request_ResourceNotFound` error is
    /// `NotFound`; authentication, transport, throttling, malformed responses,
    /// and other HTTP errors remain errors. Callers must not infer absence
    /// from those errors.
    pub async fn request_user_exact(
        &self,
        access_token: &str,
        name_or_uuid: &str,
    ) -> Result<ExactUserLookup, MsalError> {
        // URL parsers normalize even percent-encoded dot path segments.
        if name_or_uuid.is_empty() || matches!(name_or_uuid, "." | "..") {
            return Err(MsalError::URLFormatFailed(
                "an exact user lookup requires a UPN or object ID".to_string(),
            ));
        }
        let mut url = Url::parse(&format!(
            "{}/v1.0/users/{}",
            self.graph_url().await?.trim_end_matches('/'),
            percent_encoding::utf8_percent_encode(name_or_uuid, percent_encoding::NON_ALPHANUMERIC)
        ))
        .map_err(|e| MsalError::URLFormatFailed(e.to_string()))?;
        url.query_pairs_mut().append_pair(
            "$select",
            "id,displayName,userPrincipalName,onPremisesSamAccountName",
        );
        let resp = self
            .exact_client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        let status = resp.status();
        if status == StatusCode::OK {
            let user = resp
                .json::<UserObject>()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(ExactUserLookup::Found(user))
        } else if status == StatusCode::NOT_FOUND {
            let error = resp
                .json::<GraphErrorResponse>()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            if error.error.code == "Request_ResourceNotFound" {
                Ok(ExactUserLookup::NotFound)
            } else {
                Err(MsalError::GeneralFailure(status.to_string()))
            }
        } else {
            Err(MsalError::GeneralFailure(status.to_string()))
        }
    }

    pub async fn request_all_users_with_extension_attributes(
        &self,
        access_token: &str,
    ) -> Result<Vec<UserObject>, MsalError> {
        let url = Url::parse(&format!("{}/beta/users?$top=999", self.graph_url().await?))
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let objs = self
            .fetch_all_pages(url.as_str(), access_token)
            .await
            .map(|objs: Vec<Value>| objs)?;

        let mut res: Vec<UserObject> = vec![];
        for user in &objs {
            let mut userobj: UserObject = serde_json::from_value(user.clone())
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            if let Value::Object(obj) = &user {
                for (key, value) in obj.iter() {
                    if key.starts_with("extension_") {
                        if key.ends_with("uidNumber") {
                            if let Value::Number(num) = value {
                                userobj.uid = num.as_u64().map(|uid| uid as u32);
                            }
                        } else if key.ends_with("gidNumber") {
                            if let Value::Number(num) = value {
                                userobj.gid = num.as_u64().map(|gid| gid as u32);
                            }
                        }
                    }
                }
            }

            if userobj.uid.is_some() || userobj.gid.is_some() {
                res.push(userobj);
            }
        }

        Ok(res)
    }

    pub async fn request_all_groups_with_extension_attributes(
        &self,
        access_token: &str,
    ) -> Result<Vec<GroupObject>, MsalError> {
        let url = Url::parse(&format!("{}/beta/groups?$top=999", self.graph_url().await?))
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let objs = self
            .fetch_all_pages(url.as_str(), access_token)
            .await
            .map(|objs: Vec<Value>| objs)?;

        let mut res: Vec<GroupObject> = vec![];
        for user in &objs {
            let mut groupobj: GroupObject = serde_json::from_value(user.clone())
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            if let Value::Object(obj) = &user {
                for (key, value) in obj.iter() {
                    if key.starts_with("extension_") && key.ends_with("gidNumber") {
                        if let Value::Number(num) = value {
                            groupobj.gid = num.as_u64().map(|gid| gid as u32);
                        }
                    }
                }
            }

            if groupobj.gid.is_some() {
                res.push(groupobj);
            }
        }

        Ok(res)
    }

    pub async fn request_user_groups(
        &self,
        access_token: &str,
    ) -> Result<Vec<DirectoryObject>, MsalError> {
        let url = &format!("{}/v1.0/me/memberOf?$top=999", self.graph_url().await?);
        self.fetch_all_pages(url, access_token)
            .await
            .map(|objs: Vec<DirectoryObject>| objs)
    }

    pub async fn request_user_groups_by_user_id(
        &self,
        access_token: &str,
        object_id: &str,
    ) -> Result<Vec<DirectoryObject>, MsalError> {
        let url = &format!(
            "{}/v1.0/users/{}/memberOf?$top=999",
            self.graph_url().await?,
            object_id
        );
        self.fetch_all_pages(url, access_token)
            .await
            .map(|objs: Vec<DirectoryObject>| objs)
    }

    pub async fn assign_device_to_user(
        &self,
        access_token: &str,
        device_id: &str,
        upn: &str,
    ) -> Result<(), MsalError> {
        let url = &format!(
            "{}/v1.0/devices/{}/registeredOwners/$ref",
            self.graph_url().await?,
            device_id
        );
        let user_obj = self.request_user(access_token, upn).await?;
        let payload = json!({
            "@odata.id": format!("{}/v1.0/directoryObjects/{}", self.graph_url().await?, user_obj.id),
        });
        if let Ok(pretty) = to_string_pretty(&payload) {
            debug!("POST {}: {}", url, pretty);
        }
        let resp = self
            .client
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn request_group(
        &self,
        access_token: &str,
        displayname: &str,
    ) -> Result<GroupObject, MsalError> {
        let url = Url::parse_with_params(
            &format!("{}/v1.0/groups", self.graph_url().await?),
            &[("$filter", format!("displayName eq '{}'", displayname))],
        )
        .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: GroupObject = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            Ok(json_resp)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn fetch_user_profile_photo(
        &self,
        access_token: &str,
        mut file: File,
    ) -> Result<(), MsalError> {
        let url = format!("{}/v1.0/me/photo/$value", self.graph_url().await?);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let content = resp
                .bytes()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("Failed to read bytes: {:?}", e)))?;
            file.write_all(&content)
                .map_err(|e| MsalError::GeneralFailure(format!("Failed to write file: {:?}", e)))?;

            Ok(())
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn fetch_user_extension_attributes(
        &self,
        access_token: &str,
        extension_attributes: Vec<&str>,
    ) -> Result<HashMap<String, String>, MsalError> {
        let url = format!("{}/beta/me", self.graph_url().await?);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: Value = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            let mut result_map = HashMap::new();
            if let Value::Object(obj) = json_resp {
                for (key, value) in obj.iter() {
                    if key.starts_with("extension_") {
                        for &attr in &extension_attributes {
                            if key.ends_with(&format!("_{}", attr)) {
                                if let Value::String(val) = value {
                                    result_map.insert(attr.to_string(), val.clone());
                                } else if let Value::Number(num) = value {
                                    result_map.insert(attr.to_string(), num.to_string());
                                }
                            }
                        }
                    }
                }
            }

            Ok(result_map)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn fetch_user_extension_attributes_by_user_id(
        &self,
        access_token: &str,
        object_id: &str,
        extension_attributes: Vec<&str>,
    ) -> Result<HashMap<String, String>, MsalError> {
        let url = &format!("{}/beta/users/{}", self.graph_url().await?, object_id);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: Value = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            let mut result_map = HashMap::new();
            if let Value::Object(obj) = json_resp {
                for (key, value) in obj.iter() {
                    if key.starts_with("extension_") {
                        for &attr in &extension_attributes {
                            if key.ends_with(&format!("_{}", attr)) {
                                if let Value::String(val) = value {
                                    result_map.insert(attr.to_string(), val.clone());
                                } else if let Value::Number(num) = value {
                                    result_map.insert(attr.to_string(), num.to_string());
                                }
                            }
                        }
                    }
                }
            }

            Ok(result_map)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn fetch_group_extension_attributes(
        &self,
        groupname: &str,
        access_token: &str,
        extension_attributes: Vec<&str>,
    ) -> Result<HashMap<String, String>, MsalError> {
        let url = format!("{}/beta/groups/{}", self.graph_url().await?, groupname);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: Value = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            let mut result_map = HashMap::new();
            if let Value::Object(obj) = json_resp {
                for (key, value) in obj.iter() {
                    if key.starts_with("extension_") {
                        for &attr in &extension_attributes {
                            if key.ends_with(&format!("_{}", attr)) {
                                if let Value::String(val) = value {
                                    result_map.insert(attr.to_string(), val.clone());
                                } else if let Value::Number(num) = value {
                                    result_map.insert(attr.to_string(), num.to_string());
                                }
                            }
                        }
                    }
                }
            }

            Ok(result_map)
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn intune_service_endpoints(
        &self,
        access_token: &str,
    ) -> Result<IntuneServiceEndpoints, MsalError> {
        let url = format!(
            "{}/v1.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints",
            self.graph_url().await?
        );
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e))?;
        if resp.status().is_success() {
            let json_resp: IntuneServiceEndpoints = resp
                .json()
                .await
                .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
            Ok(json_resp)
        } else {
            Err(MsalError::RequestFailed(format!("{}", resp.status())))
        }
    }

    async fn fetch_with_retry(
        &self,
        url: &str,
        token: &str,
    ) -> Result<reqwest::Response, MsalError> {
        let mut attempt = 0;
        let max_attempts = 6;

        loop {
            let resp = self
                .client
                .get(url)
                .bearer_auth(token)
                .header("ConsistencyLevel", "eventual")
                .send()
                .await
                .map_err(|e| MsalError::request_failed(&e))?;

            match resp.status() {
                StatusCode::OK => return Ok(resp),
                StatusCode::TOO_MANY_REQUESTS
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::BAD_GATEWAY
                | StatusCode::GATEWAY_TIMEOUT => {
                    attempt += 1;
                    if attempt >= max_attempts {
                        return Err(MsalError::RequestFailed(format!(
                            "HTTP {} after {} attempts",
                            resp.status(),
                            attempt
                        )));
                    }
                    let wait = resp
                        .headers()
                        .get("Retry-After")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| {
                            Duration::from_millis(200u64.saturating_mul(2u64.pow(attempt.min(5))))
                        });
                    sleep(wait).await;
                }
                s => {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(MsalError::GeneralFailure(format!(
                        "Graph error {}: {}",
                        s, body
                    )));
                }
            }
        }
    }

    async fn fetch_all_pages<T: DeserializeOwned>(
        &self,
        first_url: &str,
        token: &str,
    ) -> Result<Vec<T>, MsalError> {
        let mut url = first_url.to_string();
        let mut all = Vec::<T>::new();

        loop {
            let resp = self.fetch_with_retry(&url, token).await?;
            let text = resp.text().await.map_err(|e| {
                MsalError::GeneralFailure(format!("Failed getting text from response: {:?}", e))
            })?;
            let page: GraphPage<T> = serde_json::from_str(&text).or_else(
                |_| -> std::result::Result<GraphPage<T>, MsalError> {
                    let v: Value = serde_json::from_str(&text).map_err(|e| {
                        MsalError::InvalidJson(format!("Failed parsing page: {:?}", e))
                    })?;
                    let value = v
                        .get("value")
                        .cloned()
                        .ok_or_else(|| MsalError::GeneralFailure("missing 'value'".to_string()))?;
                    let next = v
                        .get("@odata.nextLink")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string());
                    let items: Vec<T> = serde_json::from_value(value).map_err(|e| {
                        MsalError::InvalidJson(format!("Failed parsing page: {:?}", e))
                    })?;
                    Ok(GraphPage {
                        value: items,
                        next_link: next,
                    })
                },
            )?;

            all.extend(page.value);
            if let Some(next) = page.next_link {
                url = next;
            } else {
                break;
            }
        }

        Ok(all)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    async fn mock_graph(status: StatusCode, body: String) -> (Graph, JoinHandle<String>) {
        mock_graph_with_headers(status, body, String::new()).await
    }

    async fn mock_graph_with_headers(
        status: StatusCode,
        body: String,
        headers: String,
    ) -> (Graph, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buf = [0; 1024];
                let count = socket.read(&mut buf).await.unwrap();
                assert!(count > 0, "connection closed before the request headers");
                request.extend_from_slice(&buf[..count]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 16 * 1024, "request headers too large");
            }
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
                status,
                body.len(),
                headers,
                body,
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        let graph = mock_graph_at(&format!("http://{}/", address)).await;
        (graph, server)
    }

    async fn mock_graph_at(url: &str) -> Graph {
        Graph::new(
            "unused.test",
            "example.com",
            Some("https://login.microsoftonline.com"),
            Some("test-tenant"),
            Some(url),
            #[cfg(feature = "set_timeout")]
            Duration::from_secs(2),
            #[cfg(feature = "ipvers")]
            &[IpVersion::V4],
        )
        .await
        .unwrap()
    }

    fn user_response() -> Value {
        json!({
            "id": "test-user-id",
            "displayName": "Test User",
            "userPrincipalName": "test@example.com",
        })
    }

    #[tokio::test]
    async fn request_user_selects_sam_and_encodes_the_upn() {
        let mut body = user_response();
        body["onPremisesSamAccountName"] = json!("test-user");
        let (graph, server) = mock_graph(StatusCode::OK, body.to_string()).await;
        let user = graph
            .request_user("test-access-token", "test+guest#EXT#@example.com")
            .await
            .unwrap();
        assert_eq!(user.id, "test-user-id");
        assert_eq!(user.displayname, "Test User");
        assert_eq!(user.upn, "test@example.com");
        assert_eq!(
            user.on_premises_sam_account_name.as_deref(),
            Some("test-user")
        );
        let request = server.await.unwrap();
        let target = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let url = Url::parse(&format!("http://localhost{}", target)).unwrap();
        assert_eq!(
            url.path(),
            "/v1.0/users/test%2Bguest%23EXT%23%40example%2Ecom"
        );
        assert_eq!(
            url.query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>(),
            vec![(
                "$select".to_string(),
                "id,displayName,userPrincipalName,onPremisesSamAccountName".to_string()
            )]
        );
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer test-access-token\r\n"));
    }

    #[tokio::test]
    async fn request_user_allows_missing_or_null_sam() {
        for sam in [None, Some(Value::Null)] {
            let mut body = user_response();
            if let Some(sam) = sam {
                body["onPremisesSamAccountName"] = sam;
            }
            let (graph, server) = mock_graph(StatusCode::OK, body.to_string()).await;
            let user = graph
                .request_user("test-access-token", "test@example.com")
                .await
                .unwrap();
            assert!(user.on_premises_sam_account_name.is_none());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_does_not_treat_http_failure_as_missing_sam() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            // Even a valid user body must not hide an unsuccessful HTTP status.
            let (graph, server) = mock_graph(status, user_response().to_string()).await;
            let result = graph
                .request_user("test-access-token", "test@example.com")
                .await;
            assert!(
                matches!(result, Err(MsalError::GeneralFailure(message)) if message == status.to_string())
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_does_not_treat_invalid_response_as_missing_sam() {
        let (graph, server) = mock_graph(StatusCode::OK, "{}".to_string()).await;
        let result = graph
            .request_user("test-access-token", "test@example.com")
            .await;
        assert!(matches!(result, Err(MsalError::InvalidJson(_))));
        server.await.unwrap();
    }

    fn not_found_response() -> String {
        json!({
            "error": {
                "code": "Request_ResourceNotFound",
                "message": "Resource does not exist.",
                "innerError": {"request-id": "test-request-id"},
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn request_user_exact_selects_identity_and_preserves_returned_upn() {
        let object_id = "11111111-2222-3333-4444-555555555555";
        for query in [
            "test+guest#EXT#@example.com",
            "first'last/with?query%fragment@example.com",
            "døe@example.com",
            object_id,
        ] {
            let mut body = user_response();
            body["id"] = json!(object_id);
            body["userPrincipalName"] = json!("actual.identity@example.com");
            body["onPremisesSamAccountName"] = json!("legacy-sam");
            let (graph, server) = mock_graph(StatusCode::OK, body.to_string()).await;
            let result = graph
                .request_user_exact("test-access-token", query)
                .await
                .unwrap();
            let ExactUserLookup::Found(user) = result else {
                panic!("successful user response was not Found");
            };
            assert_eq!(user.id, object_id);
            assert_eq!(user.upn, "actual.identity@example.com");
            assert_eq!(user.displayname, "Test User");
            assert_eq!(
                user.on_premises_sam_account_name.as_deref(),
                Some("legacy-sam")
            );
            let request = server.await.unwrap();
            let target = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let url = Url::parse(&format!("http://localhost{}", target)).unwrap();
            assert_eq!(
                url.path(),
                format!(
                    "/v1.0/users/{}",
                    percent_encoding::utf8_percent_encode(
                        query,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                )
            );
            assert_eq!(
                url.query_pairs().into_owned().collect::<Vec<_>>(),
                vec![(
                    "$select".to_string(),
                    "id,displayName,userPrincipalName,onPremisesSamAccountName".to_string()
                )]
            );
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer test-access-token\r\n"));
        }
    }

    #[tokio::test]
    async fn request_user_exact_allows_missing_or_null_sam_on_found_user() {
        for sam in [None, Some(Value::Null)] {
            let mut body = user_response();
            if let Some(sam) = sam {
                body["onPremisesSamAccountName"] = sam;
            }
            let (graph, server) = mock_graph(StatusCode::OK, body.to_string()).await;
            let result = graph
                .request_user_exact("test-token", "test@example.com")
                .await
                .unwrap();
            assert!(
                matches!(result, ExactUserLookup::Found(user) if user.on_premises_sam_account_name.is_none())
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_exact_accepts_only_structured_graph_not_found() {
        let (graph, server) = mock_graph(StatusCode::NOT_FOUND, not_found_response()).await;
        let result = graph
            .request_user_exact("test-token", "test@example.com")
            .await
            .unwrap();
        assert!(matches!(result, ExactUserLookup::NotFound));
        server.await.unwrap();

        for body in [
            "",
            "not-json",
            "{}",
            r#"{"error":null}"#,
            r#"{"error":"Request_ResourceNotFound"}"#,
            r#"{"error":{"code":"Request_ResourceNotFound"}}"#,
            r#"{"error":{"code":"Request_ResourceNotFound","message":null}}"#,
            r#"{"error":{"code":404,"message":"Request_ResourceNotFound"}}"#,
            r#"{"error":{"code":"Request_ResourceNotFound","code":"other","message":"missing"}}"#,
            r#"{"error":{"code":"request_resourcenotfound","message":"missing"}}"#,
            r#"{"error":{"code":"ResourceNotFound","message":"missing"}}"#,
            r#"{"error":{"code":"Authorization_RequestDenied","message":"Request_ResourceNotFound"}}"#,
            r#"{"error":{"code":"unknown","message":"missing","innerError":{"code":"Request_ResourceNotFound"}}}"#,
        ] {
            let (graph, server) = mock_graph(StatusCode::NOT_FOUND, body.to_string()).await;
            let result = graph
                .request_user_exact("test-token", "test@example.com")
                .await;
            assert!(result.is_err(), "untrusted 404 became absence: {body}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_exact_never_turns_other_http_statuses_into_absence() {
        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::PARTIAL_CONTENT,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::NOT_MODIFIED,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let (graph, server) = mock_graph(status, not_found_response()).await;
            let result = graph
                .request_user_exact("test-token", "test@example.com")
                .await;
            assert!(
                matches!(result, Err(MsalError::GeneralFailure(message)) if message == status.to_string())
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_exact_rejects_invalid_success_bodies() {
        for body in [
            "not-json",
            "{}",
            r#"{"id":"id","displayName":"name"}"#,
            r#"{"id":"id","userPrincipalName":"test@example.com"}"#,
            r#"{"displayName":"name","userPrincipalName":"test@example.com"}"#,
            r#"{"id":"id","displayName":"name","userPrincipalName":"test@example.com","onPremisesSamAccountName":42}"#,
            &not_found_response(),
        ] {
            let (graph, server) = mock_graph(StatusCode::OK, body.to_string()).await;
            let result = graph
                .request_user_exact("test-token", "test@example.com")
                .await;
            assert!(matches!(result, Err(MsalError::InvalidJson(_))));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_user_exact_does_not_follow_redirects() {
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::SEE_OTHER,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let location = format!(
                "Location: http://{}/v1.0/users/other\r\n",
                target.local_addr().unwrap()
            );
            let (graph, server) =
                mock_graph_with_headers(status, not_found_response(), location).await;
            let result = graph
                .request_user_exact("test-token", "test@example.com")
                .await;
            assert!(
                matches!(result, Err(MsalError::GeneralFailure(message)) if message == status.to_string())
            );
            server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), target.accept())
                    .await
                    .is_err(),
                "redirect target received a request"
            );
        }
    }

    #[tokio::test]
    async fn request_user_preserves_existing_redirect_behavior() {
        let (target, target_server) = mock_graph(StatusCode::OK, user_response().to_string()).await;
        let location = format!(
            "Location: {}v1.0/users/other\r\n",
            target.graph_url().await.unwrap()
        );
        let (graph, server) =
            mock_graph_with_headers(StatusCode::FOUND, String::new(), location).await;
        let user = graph
            .request_user("test-token", "test@example.com")
            .await
            .unwrap();
        assert_eq!(user.upn, "test@example.com");
        server.await.unwrap();
        target_server.await.unwrap();
    }

    #[tokio::test]
    async fn request_user_exact_transport_failure_is_not_absence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let graph = mock_graph_at(&format!("http://{}", listener.local_addr().unwrap())).await;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            socket.read(&mut buffer).await.unwrap();
            // Close without providing any HTTP response.
        });
        let result = graph
            .request_user_exact("test-token", "test@example.com")
            .await;
        assert!(matches!(result, Err(MsalError::RequestFailed(_))));
        server.await.unwrap();
    }

    #[cfg(feature = "set_timeout")]
    #[tokio::test]
    async fn request_user_exact_honors_configured_timeout_without_absence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let graph = Graph::new(
            "unused.test",
            "example.com",
            Some("https://login.microsoftonline.com"),
            Some("test-tenant"),
            Some(&url),
            Duration::from_millis(50),
            #[cfg(feature = "ipvers")]
            &[IpVersion::V4],
        )
        .await
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            socket.read(&mut buffer).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            graph.request_user_exact("test-token", "test@example.com"),
        )
        .await
        .expect("configured request timeout was ignored");
        assert!(matches!(result, Err(MsalError::RequestFailed(_))));
        server.abort();
    }

    #[tokio::test]
    async fn request_user_exact_truncated_not_found_body_is_not_absence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let graph = mock_graph_at(&format!("http://{}", listener.local_addr().unwrap())).await;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            socket.read(&mut buffer).await.unwrap();
            let body = not_found_response();
            let response = format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len() + 10, body);
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let result = graph
            .request_user_exact("test-token", "test@example.com")
            .await;
        assert!(matches!(result, Err(MsalError::InvalidJson(_))));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn request_user_exact_rejects_empty_or_dot_path_segments() {
        let graph = mock_graph_at("http://127.0.0.1:1").await;
        for query in ["", ".", ".."] {
            let result = graph.request_user_exact("test-token", query).await;
            assert!(matches!(result, Err(MsalError::URLFormatFailed(_))));
        }
    }
}
