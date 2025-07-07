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
use reqwest::{header, Client, Url};
use serde::de::Error;
use serde::Deserialize;
use serde_json::{json, to_string_pretty};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error};

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

#[derive(Debug, Deserialize)]
struct DirectoryObjects {
    value: Vec<DirectoryObject>,
}

#[derive(Debug, Deserialize)]
pub struct Objects {
    value: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct UserObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    #[serde(rename = "userPrincipalName")]
    pub upn: String,
    pub id: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
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
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
    ) -> Result<Self, MsalError> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3));

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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

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
        let url = &format!("{}/v1.0/users/{}", self.graph_url().await?, upn);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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

    pub async fn request_all_users_with_extension_attributes(
        &self,
        access_token: &str,
    ) -> Result<Vec<UserObject>, MsalError> {
        let url = Url::parse(&format!("{}/beta/users", self.graph_url().await?))
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        if resp.status().is_success() {
            let json_resp: Objects = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            let mut res: Vec<UserObject> = vec![];
            for user in &json_resp.value {
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
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn request_all_groups_with_extension_attributes(
        &self,
        access_token: &str,
    ) -> Result<Vec<GroupObject>, MsalError> {
        let url = Url::parse(&format!("{}/beta/groups", self.graph_url().await?))
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

        if resp.status().is_success() {
            let json_resp: Objects = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;

            let mut res: Vec<GroupObject> = vec![];
            for user in &json_resp.value {
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
        } else {
            Err(MsalError::GeneralFailure(format!("{}", resp.status())))
        }
    }

    pub async fn request_user_groups(
        &self,
        access_token: &str,
    ) -> Result<Vec<DirectoryObject>, MsalError> {
        let url = &format!("{}/v1.0/me/memberOf", self.graph_url().await?);
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
        let mut res: Vec<DirectoryObject> = Vec::new();
        if resp.status().is_success() {
            let json_resp: DirectoryObjects = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            for entry in json_resp.value {
                if entry.data_type == "#microsoft.graph.group" {
                    res.push(entry)
                }
            }
            Ok(res)
        } else {
            let status = resp.status();
            error!(
                "Error encountered while fetching user groups: {}",
                resp.text()
                    .await
                    .map_err(|e| { MsalError::GeneralFailure(format!("{:?}", e)) })?
            );
            Err(MsalError::GeneralFailure(format!("{}", status)))
        }
    }

    pub async fn request_user_groups_by_user_id(
        &self,
        access_token: &str,
        object_id: &str,
    ) -> Result<Vec<DirectoryObject>, MsalError> {
        let url = &format!(
            "{}/v1.0/users/{}/memberOf",
            self.graph_url().await?,
            object_id
        );
        let resp = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
        let mut res: Vec<DirectoryObject> = Vec::new();
        if resp.status().is_success() {
            let json_resp: DirectoryObjects = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{:?}", e)))?;
            for entry in json_resp.value {
                if entry.data_type == "#microsoft.graph.group" {
                    res.push(entry)
                }
            }
            Ok(res)
        } else {
            let status = resp.status();
            error!(
                "Error encountered while fetching user groups: {}",
                resp.text()
                    .await
                    .map_err(|e| { MsalError::GeneralFailure(format!("{:?}", e)) })?
            );
            Err(MsalError::GeneralFailure(format!("{}", status)))
        }
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
}
