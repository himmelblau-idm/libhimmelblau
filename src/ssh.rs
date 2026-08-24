/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@suse.com> 2026

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
*/

use crate::error::MsalError;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use base64::Engine;
use openssl::sha::sha256;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const SSH_RSA_KEY_TYPE: &str = "ssh-rsa";
pub const SSH_RSA_CERT_KEY_TYPE: &str = "ssh-rsa-cert-v01@openssh.com";
pub(crate) const AZURE_CLI_APP_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
pub(crate) const AAD_SSH_LOGIN_APP_ID: &str = "ce6ff14a-7fdc-4685-bbe0-f6afdfcfa8e0";
const SSH_CERT_CLAIMS: &str = r#"{"access_token":{"xms_cc":{"values":["CP1"]}}}"#;
const MAX_SSH_CERTIFICATE_LEN: usize = 64 * 1024;
const MAX_SSH_CERTIFICATE_BASE64_LEN: usize = MAX_SSH_CERTIFICATE_LEN.div_ceil(3) * 4;
const MAX_SSH_STRING_LEN: usize = 16 * 1024;

#[derive(Clone)]
pub struct EntraSshCertificate {
    pub certificate_body_base64: String,
    pub request_key_id: String,
    pub certificate_key_id: String,
    pub serial: u64,
    pub principals: Vec<String>,
    pub tenant_id: Uuid,
    pub object_id: Uuid,
    pub display_name: Option<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub expires_in: u32,
    pub ext_expires_in: u32,
    pub scope: Option<String>,
    pub signing_ca_openssh_public_key: String,
    pub signing_ca_fingerprint_sha256: String,
}

impl EntraSshCertificate {
    pub fn openssh_certificate(&self) -> String {
        format!("{} {}", SSH_RSA_CERT_KEY_TYPE, self.certificate_body_base64)
    }

    pub fn signing_ca_openssh_public_key(&self) -> &str {
        &self.signing_ca_openssh_public_key
    }
}

impl fmt::Debug for EntraSshCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraSshCertificate")
            .field("certificate_body_base64", &"<redacted>")
            .field("request_key_id", &self.request_key_id)
            .field("certificate_key_id", &self.certificate_key_id)
            .field("serial", &self.serial)
            .field("principals", &self.principals)
            .field("tenant_id", &self.tenant_id)
            .field("object_id", &self.object_id)
            .field("display_name", &self.display_name)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .field("expires_in", &self.expires_in)
            .field("ext_expires_in", &self.ext_expires_in)
            .field("scope", &self.scope)
            .field(
                "signing_ca_openssh_public_key",
                &self.signing_ca_openssh_public_key,
            )
            .field(
                "signing_ca_fingerprint_sha256",
                &self.signing_ca_fingerprint_sha256,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SshRsaJwk {
    pub kty: &'static str,
    pub n: String,
    pub e: String,
    pub kid: String,
}

#[derive(Serialize)]
struct SshCertificateRequestForm<'a> {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: &'a str,
    client_info: &'static str,
    scope: String,
    token_type: &'static str,
    key_id: &'a str,
    req_cnf: String,
    claims: &'static str,
}

pub(crate) fn build_ssh_certificate_request_form(
    refresh_token: &str,
    jwk: &SshRsaJwk,
) -> Result<String, MsalError> {
    let req_cnf = serde_json::to_string(jwk).map_err(|e| {
        MsalError::InvalidJson(format!("Failed serializing SSH public-key JWK: {}", e))
    })?;
    serde_urlencoded::to_string(SshCertificateRequestForm {
        client_id: AZURE_CLI_APP_ID,
        grant_type: "refresh_token",
        refresh_token,
        client_info: "1",
        scope: format!(
            "{}/.default offline_access openid profile",
            AAD_SSH_LOGIN_APP_ID
        ),
        token_type: "ssh-cert",
        key_id: &jwk.kid,
        req_cnf,
        claims: SSH_CERT_CLAIMS,
    })
    .map_err(|e| MsalError::InvalidParse(format!("Failed encoding SSH certificate request: {}", e)))
}

fn deserialize_u32_number_or_string<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(u32),
        String(String),
    }

    match NumberOrString::deserialize(deserializer)? {
        NumberOrString::Number(value) => Ok(value),
        NumberOrString::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn deserialize_certificate_body<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct CertificateBodyVisitor;

    impl Visitor<'_> for CertificateBodyVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a base64 SSH certificate no longer than {} bytes",
                MAX_SSH_CERTIFICATE_BASE64_LEN
            )
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_SSH_CERTIFICATE_BASE64_LEN {
                return Err(E::custom("SSH certificate body exceeds size limit"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_SSH_CERTIFICATE_BASE64_LEN {
                return Err(E::custom("SSH certificate body exceeds size limit"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_str(CertificateBodyVisitor)
}

#[derive(Deserialize)]
pub(crate) struct SshCertificateTokenResponse {
    pub token_type: String,
    pub scope: Option<String>,
    #[serde(deserialize_with = "deserialize_u32_number_or_string")]
    pub expires_in: u32,
    #[serde(deserialize_with = "deserialize_u32_number_or_string")]
    pub ext_expires_in: u32,
    #[serde(
        rename = "access_token",
        deserialize_with = "deserialize_certificate_body"
    )]
    pub certificate_body_base64: String,
}

struct SshReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SshReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], MsalError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| MsalError::InvalidParse("SSH field length overflow".to_string()))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| MsalError::InvalidParse("Truncated SSH wire value".to_string()))?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, MsalError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| MsalError::InvalidParse("Invalid SSH uint32".to_string()))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, MsalError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| MsalError::InvalidParse("Invalid SSH uint64".to_string()))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn string(&mut self) -> Result<&'a [u8], MsalError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| MsalError::InvalidParse("Invalid SSH string length".to_string()))?;
        if len > MAX_SSH_STRING_LEN {
            return Err(MsalError::InvalidParse(
                "SSH string exceeds size limit".to_string(),
            ));
        }
        self.take(len)
    }

    fn text(&mut self, name: &str) -> Result<String, MsalError> {
        String::from_utf8(self.string()?.to_vec())
            .map_err(|e| MsalError::InvalidParse(format!("Invalid UTF-8 in {}: {}", name, e)))
    }

    fn finish(self) -> Result<(), MsalError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(MsalError::InvalidParse(
                "Trailing data in SSH wire value".to_string(),
            ))
        }
    }
}

fn positive_mpint<'a>(value: &'a [u8], name: &str) -> Result<&'a [u8], MsalError> {
    if value.is_empty() {
        return Err(MsalError::InvalidParse(format!(
            "SSH RSA {} must be positive",
            name
        )));
    }
    if value[0] == 0 {
        if value.len() == 1 {
            return Err(MsalError::InvalidParse(format!(
                "SSH RSA {} must be positive",
                name
            )));
        }
        if value[1] & 0x80 == 0 {
            return Err(MsalError::InvalidParse(format!(
                "SSH RSA {} has redundant mpint padding",
                name
            )));
        }
        return Ok(&value[1..]);
    }
    if value[0] & 0x80 != 0 {
        return Err(MsalError::InvalidParse(format!(
            "SSH RSA {} is a negative mpint",
            name
        )));
    }
    Ok(value)
}

fn parse_rsa_blob<'a>(
    blob: &'a [u8],
    expected_type: &str,
) -> Result<(&'a [u8], &'a [u8]), MsalError> {
    let mut reader = SshReader::new(blob);
    let key_type = reader.text("SSH key type")?;
    if key_type != expected_type {
        return Err(MsalError::InvalidParse(format!(
            "Expected {}, received {}",
            expected_type, key_type
        )));
    }
    let exponent = positive_mpint(reader.string()?, "exponent")?;
    let modulus = positive_mpint(reader.string()?, "modulus")?;
    reader.finish()?;
    Ok((exponent, modulus))
}

pub(crate) fn ssh_rsa_public_key_to_jwk(public_key: &str) -> Result<SshRsaJwk, MsalError> {
    let mut fields = public_key.split_whitespace();
    let key_type = fields
        .next()
        .ok_or_else(|| MsalError::InvalidParse("OpenSSH public key type missing".to_string()))?;
    if key_type != SSH_RSA_KEY_TYPE {
        return Err(MsalError::InvalidParse(format!(
            "Only {} public keys are supported",
            SSH_RSA_KEY_TYPE
        )));
    }
    let body = fields
        .next()
        .ok_or_else(|| MsalError::InvalidParse("OpenSSH public key body missing".to_string()))?;
    let blob = STANDARD
        .decode(body)
        .map_err(|e| MsalError::InvalidBase64(format!("Invalid OpenSSH public key: {}", e)))?;
    let (exponent, modulus) = parse_rsa_blob(&blob, SSH_RSA_KEY_TYPE)?;
    let n = URL_SAFE.encode(modulus);
    let e = URL_SAFE.encode(exponent);
    let digest = sha256(format!("{}{}", n, e).as_bytes());
    let kid = digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("");

    Ok(SshRsaJwk {
        kty: "RSA",
        n,
        e,
        kid,
    })
}

fn parse_string_list(bytes: &[u8], field: &str) -> Result<Vec<String>, MsalError> {
    let mut reader = SshReader::new(bytes);
    let mut values = Vec::new();
    while reader.offset < reader.bytes.len() {
        values.push(reader.text(field)?);
    }
    reader.finish()?;
    Ok(values)
}

fn parse_extension_text(value: &[u8], name: &str) -> Result<String, MsalError> {
    let mut reader = SshReader::new(value);
    let text = reader.text(name)?;
    reader.finish()?;
    Ok(text)
}

pub(crate) fn parse_ssh_certificate_response(
    response: SshCertificateTokenResponse,
    requested_jwk: &SshRsaJwk,
) -> Result<EntraSshCertificate, MsalError> {
    if response.token_type != "ssh-cert" {
        return Err(MsalError::InvalidParse(format!(
            "Expected ssh-cert token type, received {}",
            response.token_type
        )));
    }
    if response.certificate_body_base64.len() > MAX_SSH_CERTIFICATE_BASE64_LEN {
        return Err(MsalError::InvalidParse(
            "SSH certificate body exceeds size limit".to_string(),
        ));
    }
    let blob = STANDARD
        .decode(&response.certificate_body_base64)
        .map_err(|e| MsalError::InvalidBase64(format!("Invalid SSH certificate body: {}", e)))?;
    if blob.len() > MAX_SSH_CERTIFICATE_LEN {
        return Err(MsalError::InvalidParse(
            "SSH certificate exceeds size limit".to_string(),
        ));
    }
    let mut reader = SshReader::new(&blob);
    let key_type = reader.text("SSH certificate key type")?;
    if key_type != SSH_RSA_CERT_KEY_TYPE {
        return Err(MsalError::InvalidParse(format!(
            "Expected {}, received {}",
            SSH_RSA_CERT_KEY_TYPE, key_type
        )));
    }
    let _nonce = reader.string()?;
    let exponent = positive_mpint(reader.string()?, "certificate exponent")?;
    let modulus = positive_mpint(reader.string()?, "certificate modulus")?;
    if URL_SAFE.encode(modulus) != requested_jwk.n || URL_SAFE.encode(exponent) != requested_jwk.e {
        return Err(MsalError::InvalidParse(
            "SSH certificate public key does not match the requested key".to_string(),
        ));
    }
    let serial = reader.u64()?;
    if reader.u32()? != 1 {
        return Err(MsalError::InvalidParse(
            "Entra returned an SSH host certificate instead of a user certificate".to_string(),
        ));
    }
    let certificate_key_id = reader.text("SSH certificate key id")?;
    let principals = parse_string_list(reader.string()?, "SSH certificate principal")?;
    if principals.is_empty() || principals.iter().any(String::is_empty) {
        return Err(MsalError::InvalidParse(
            "SSH certificate contains no principals".to_string(),
        ));
    }
    let valid_after = reader.u64()?;
    let valid_before = reader.u64()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MsalError::GeneralFailure(format!("System clock before unix epoch: {}", e)))?
        .as_secs();
    if valid_before <= valid_after
        || now < valid_after
        || valid_before <= now
        || valid_before == u64::MAX
    {
        return Err(MsalError::InvalidParse(
            "SSH certificate has an invalid or expired lifetime".to_string(),
        ));
    }
    let _critical_options = reader.string()?;
    let extensions_blob = reader.string()?;
    let _reserved = reader.string()?;
    let signature_key = reader.string()?;
    let _signature = reader.string()?;
    reader.finish()?;
    parse_rsa_blob(signature_key, SSH_RSA_KEY_TYPE).map_err(|_| {
        MsalError::InvalidParse("SSH certificate signing key is not a valid RSA key".to_string())
    })?;

    let mut tenant_id = None;
    let mut object_id = None;
    let mut display_name = None;
    let mut extensions = SshReader::new(extensions_blob);
    while extensions.offset < extensions.bytes.len() {
        let name = extensions.text("SSH certificate extension name")?;
        let value = extensions.string()?;
        match name.as_str() {
            "tid@sshservice.azure.net" => {
                if tenant_id.is_some() {
                    return Err(MsalError::InvalidParse(
                        "SSH certificate contains duplicate tenant id extensions".to_string(),
                    ));
                }
                tenant_id = Some(
                    Uuid::parse_str(&parse_extension_text(value, &name)?).map_err(|e| {
                        MsalError::InvalidParse(format!("Invalid SSH tenant id: {}", e))
                    })?,
                );
            }
            "oid@sshservice.azure.net" => {
                if object_id.is_some() {
                    return Err(MsalError::InvalidParse(
                        "SSH certificate contains duplicate object id extensions".to_string(),
                    ));
                }
                object_id = Some(
                    Uuid::parse_str(&parse_extension_text(value, &name)?).map_err(|e| {
                        MsalError::InvalidParse(format!("Invalid SSH object id: {}", e))
                    })?,
                );
            }
            "displayname@sshservice.azure.net" => {
                display_name = Some(parse_extension_text(value, &name)?);
            }
            _ => {}
        }
    }
    extensions.finish()?;

    let tenant_id = tenant_id.ok_or_else(|| {
        MsalError::InvalidParse("SSH certificate tenant id extension missing".to_string())
    })?;
    let object_id = object_id.ok_or_else(|| {
        MsalError::InvalidParse("SSH certificate object id extension missing".to_string())
    })?;
    let expected_certificate_key_id = format!("{}@{}", object_id, tenant_id);
    if certificate_key_id != expected_certificate_key_id {
        return Err(MsalError::InvalidParse(
            "SSH certificate key id does not match its object and tenant ids".to_string(),
        ));
    }
    let signing_ca_openssh_public_key =
        format!("{} {}", SSH_RSA_KEY_TYPE, STANDARD.encode(signature_key));
    let ca_digest = sha256(signature_key);
    let signing_ca_fingerprint_sha256 = format!("SHA256:{}", STANDARD_NO_PAD.encode(ca_digest));

    Ok(EntraSshCertificate {
        certificate_body_base64: response.certificate_body_base64,
        request_key_id: requested_jwk.kid.clone(),
        certificate_key_id,
        serial,
        principals,
        tenant_id,
        object_id,
        display_name,
        valid_after,
        valid_before,
        expires_in: response.expires_in,
        ext_expires_in: response.ext_expires_in,
        scope: response.scope,
        signing_ca_openssh_public_key,
        signing_ca_fingerprint_sha256,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend(value.to_be_bytes());
    }

    fn push_u64(output: &mut Vec<u8>, value: u64) {
        output.extend(value.to_be_bytes());
    }

    fn push_string(output: &mut Vec<u8>, value: &[u8]) {
        push_u32(output, value.len() as u32);
        output.extend(value);
    }

    fn rsa_blob(key_type: &str, exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        push_string(&mut blob, key_type.as_bytes());
        push_string(&mut blob, exponent);
        push_string(&mut blob, modulus);
        blob
    }

    fn public_key(exponent: &[u8], modulus: &[u8]) -> String {
        let blob = rsa_blob(SSH_RSA_KEY_TYPE, exponent, modulus);
        format!("{} {} fixture", SSH_RSA_KEY_TYPE, STANDARD.encode(blob))
    }

    fn rsa_public_key() -> String {
        public_key(&[0x01, 0x00, 0x01], &[0x00, 0x80, 0x01, 0x02, 0x03])
    }

    fn nested_text(value: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        push_string(&mut encoded, value.as_bytes());
        encoded
    }

    fn certificate_response_with(
        modulus: &[u8],
        principal_values: &[&str],
        extension_values: &[(&str, &str)],
        valid_after: u64,
        valid_before: u64,
        signature_key: &[u8],
    ) -> SshCertificateTokenResponse {
        let mut principals = Vec::new();
        for principal in principal_values {
            push_string(&mut principals, principal.as_bytes());
        }

        let mut extensions = Vec::new();
        for (name, value) in extension_values {
            push_string(&mut extensions, name.as_bytes());
            push_string(&mut extensions, &nested_text(value));
        }
        push_string(&mut extensions, b"permit-pty");
        push_string(&mut extensions, b"");

        let mut blob = Vec::new();
        push_string(&mut blob, SSH_RSA_CERT_KEY_TYPE.as_bytes());
        push_string(&mut blob, b"nonce");
        push_string(&mut blob, &[0x01, 0x00, 0x01]);
        push_string(&mut blob, modulus);
        push_u64(&mut blob, 7);
        push_u32(&mut blob, 1);
        push_string(
            &mut blob,
            b"23020401-2996-4c8a-93c1-2a897f237f61@d2aeee75-1b7b-4211-81c0-a7320a908d8e",
        );
        push_string(&mut blob, &principals);
        push_u64(&mut blob, valid_after);
        push_u64(&mut blob, valid_before);
        push_string(&mut blob, b"");
        push_string(&mut blob, &extensions);
        push_string(&mut blob, b"");
        push_string(&mut blob, signature_key);
        push_string(&mut blob, b"test-signature");

        SshCertificateTokenResponse {
            token_type: "ssh-cert".to_string(),
            scope: Some("ssh-scope".to_string()),
            expires_in: 3599,
            ext_expires_in: 3599,
            certificate_body_base64: STANDARD.encode(blob),
        }
    }

    fn default_extensions() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "tid@sshservice.azure.net",
                "d2aeee75-1b7b-4211-81c0-a7320a908d8e",
            ),
            (
                "oid@sshservice.azure.net",
                "23020401-2996-4c8a-93c1-2a897f237f61",
            ),
            ("displayname@sshservice.azure.net", "Test User"),
        ]
    }

    fn certificate_response(modulus: &[u8]) -> SshCertificateTokenResponse {
        certificate_response_with(
            modulus,
            &["user@example.com"],
            &default_extensions(),
            1,
            u64::MAX - 1,
            &rsa_blob(SSH_RSA_KEY_TYPE, &[0x01, 0x00, 0x01], &[0x00, 0x80]),
        )
    }

    #[test]
    fn openssh_rsa_key_builds_azure_compatible_jwk() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.n, "gAECAw==");
        assert_eq!(jwk.e, "AQAB");
        assert_eq!(format!("{}{}", jwk.n, jwk.e), "gAECAw==AQAB");
        assert_eq!(
            jwk.kid,
            "96bdb0cdc75cfefd771d9538610eb75d6953ade551b2ab1d219ae940a09f2cae"
        );
        assert_eq!(
            serde_json::to_string(&jwk).unwrap(),
            format!(
                r#"{{"kty":"RSA","n":"gAECAw==","e":"AQAB","kid":"{}"}}"#,
                jwk.kid
            )
        );
    }

    #[test]
    fn openssh_rsa_key_rejects_invalid_mpints() {
        assert!(ssh_rsa_public_key_to_jwk(&public_key(&[0], &[1])).is_err());
        assert!(ssh_rsa_public_key_to_jwk(&public_key(&[1], &[0x80])).is_err());
        assert!(ssh_rsa_public_key_to_jwk(&public_key(&[1], &[0, 1])).is_err());
    }

    #[test]
    fn ssh_certificate_request_form_matches_captured_protocol() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        let form = build_ssh_certificate_request_form("secret-refresh-token", &jwk).unwrap();
        let values: HashMap<String, String> = serde_urlencoded::from_str(&form).unwrap();
        assert_eq!(values["client_id"], AZURE_CLI_APP_ID);
        assert_eq!(values["grant_type"], "refresh_token");
        assert_eq!(values["refresh_token"], "secret-refresh-token");
        assert_eq!(values["client_info"], "1");
        assert_eq!(
            values["scope"],
            format!(
                "{}/.default offline_access openid profile",
                AAD_SSH_LOGIN_APP_ID
            )
        );
        assert_eq!(values["token_type"], "ssh-cert");
        assert_eq!(values["key_id"], jwk.kid);
        assert_eq!(values["req_cnf"], serde_json::to_string(&jwk).unwrap());
        assert_eq!(values["claims"], SSH_CERT_CLAIMS);
    }

    #[test]
    fn openssh_rsa_key_rejects_wrong_type_and_trailing_wire_data() {
        assert!(ssh_rsa_public_key_to_jwk("ssh-ed25519 AAAA").is_err());
        let mut key = rsa_public_key();
        key = key.replacen(" fixture", "", 1);
        let mut fields = key.split_whitespace();
        let key_type = fields.next().unwrap();
        let mut blob = STANDARD.decode(fields.next().unwrap()).unwrap();
        blob.push(0);
        assert!(
            ssh_rsa_public_key_to_jwk(&format!("{} {}", key_type, STANDARD.encode(blob))).is_err()
        );
    }

    #[test]
    fn ssh_certificate_response_is_parsed_and_bound_to_request_key() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        let certificate = parse_ssh_certificate_response(
            certificate_response(&[0x00, 0x80, 0x01, 0x02, 0x03]),
            &jwk,
        )
        .unwrap();
        assert_eq!(certificate.serial, 7);
        assert_eq!(certificate.principals, vec!["user@example.com"]);
        assert_eq!(
            certificate.tenant_id.to_string(),
            "d2aeee75-1b7b-4211-81c0-a7320a908d8e"
        );
        assert_eq!(
            certificate.object_id.to_string(),
            "23020401-2996-4c8a-93c1-2a897f237f61"
        );
        assert_eq!(certificate.display_name.as_deref(), Some("Test User"));
        assert!(certificate
            .openssh_certificate()
            .starts_with("ssh-rsa-cert-v01@openssh.com "));
        assert!(certificate
            .signing_ca_fingerprint_sha256
            .starts_with("SHA256:"));
        assert_eq!(
            certificate.signing_ca_openssh_public_key(),
            format!(
                "{} {}",
                SSH_RSA_KEY_TYPE,
                STANDARD.encode(rsa_blob(
                    SSH_RSA_KEY_TYPE,
                    &[0x01, 0x00, 0x01],
                    &[0x00, 0x80]
                ))
            )
        );
        assert!(!format!("{:?}", certificate).contains(&certificate.certificate_body_base64));
    }

    #[test]
    fn ssh_certificate_response_rejects_mismatched_key_and_token_type() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        assert!(parse_ssh_certificate_response(certificate_response(&[9, 9, 9]), &jwk).is_err());
        let mut response = certificate_response(&[0x00, 0x80, 0x01, 0x02, 0x03]);
        response.token_type = "Bearer".to_string();
        assert!(parse_ssh_certificate_response(response, &jwk).is_err());
    }

    #[test]
    fn ssh_certificate_response_rejects_invalid_metadata() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        let modulus = [0x00, 0x80, 0x01, 0x02, 0x03];
        let ca = rsa_blob(SSH_RSA_KEY_TYPE, &[0x01, 0x00, 0x01], &[0x00, 0x80]);

        let empty_principal =
            certificate_response_with(&modulus, &[""], &default_extensions(), 1, u64::MAX - 1, &ca);
        assert!(parse_ssh_certificate_response(empty_principal, &jwk).is_err());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future = certificate_response_with(
            &modulus,
            &["user@example.com"],
            &default_extensions(),
            now + 60,
            now + 3600,
            &ca,
        );
        assert!(parse_ssh_certificate_response(future, &jwk).is_err());

        let mut duplicate_extensions = default_extensions();
        duplicate_extensions.push((
            "tid@sshservice.azure.net",
            "d2aeee75-1b7b-4211-81c0-a7320a908d8e",
        ));
        let duplicate = certificate_response_with(
            &modulus,
            &["user@example.com"],
            &duplicate_extensions,
            1,
            u64::MAX - 1,
            &ca,
        );
        assert!(parse_ssh_certificate_response(duplicate, &jwk).is_err());

        let non_rsa_ca = rsa_blob("ssh-ed25519", &[1], &[1]);
        let unexpected_ca = certificate_response_with(
            &modulus,
            &["user@example.com"],
            &default_extensions(),
            1,
            u64::MAX - 1,
            &non_rsa_ca,
        );
        assert!(parse_ssh_certificate_response(unexpected_ca, &jwk).is_err());
    }

    #[test]
    fn ssh_certificate_response_rejects_oversized_values() {
        let jwk = ssh_rsa_public_key_to_jwk(&rsa_public_key()).unwrap();
        let mut response = certificate_response(&[0x00, 0x80, 0x01, 0x02, 0x03]);
        response.certificate_body_base64 = "A".repeat(MAX_SSH_CERTIFICATE_BASE64_LEN + 1);
        assert!(parse_ssh_certificate_response(response, &jwk).is_err());

        let oversized_principal = "x".repeat(MAX_SSH_STRING_LEN + 1);
        let response = certificate_response_with(
            &[0x00, 0x80, 0x01, 0x02, 0x03],
            &[&oversized_principal],
            &default_extensions(),
            1,
            u64::MAX - 1,
            &rsa_blob(SSH_RSA_KEY_TYPE, &[0x01, 0x00, 0x01], &[0x00, 0x80]),
        );
        assert!(parse_ssh_certificate_response(response, &jwk).is_err());
    }

    #[test]
    fn ssh_token_response_accepts_numeric_strings() {
        let response: SshCertificateTokenResponse = serde_json::from_str(
            r#"{"token_type":"ssh-cert","expires_in":"3599","ext_expires_in":"3599","access_token":"AA=="}"#,
        )
        .unwrap();
        assert_eq!(response.expires_in, 3599);
    }
}
