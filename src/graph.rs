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
use reqwest::{header, Client, Url};
use serde::Deserialize;
use serde_json::{json, to_string_pretty};
use tokio::sync::RwLock;
use tracing::{debug, error};

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

#[derive(Debug, Deserialize)]
pub struct DirectoryObject {
    #[serde(rename = "@odata.type")]
    pub data_type: String,
    pub id: String,
    pub description: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "securityIdentifier")]
    pub security_identifier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DirectoryObjects {
    value: Vec<DirectoryObject>,
}

#[derive(Debug, Deserialize)]
pub struct UserObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    #[serde(rename = "userPrincipalName")]
    pub upn: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct GroupObject {
    #[serde(rename = "displayName")]
    pub displayname: String,
    pub id: String,
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
    .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;

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
        Err(MsalError::RequestFailed(format!(
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
        let mut federation_provider = $graph.federation_provider.write().await;
        if federation_provider.is_none() {
            *federation_provider =
                federation_provider_or_none!($graph.client, &$graph.odc_provider, &$graph.domain);
        }
        match &*$graph.federation_provider.read().await {
            Some(federation_provider) => Ok(federation_provider.$val.clone()),
            None => Err(MsalError::RequestFailed(
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
        let client = reqwest::Client::builder()
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
            Err(MsalError::RequestFailed(format!("{}", resp.status())))
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
            Err(MsalError::RequestFailed(format!("{}", status)))
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
            Err(MsalError::RequestFailed(format!("{}", resp.status())))
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
        .map_err(|e| MsalError::RequestFailed(format!("{:?}", e)))?;
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
            Err(MsalError::RequestFailed(format!("{}", resp.status())))
        }
    }
}
