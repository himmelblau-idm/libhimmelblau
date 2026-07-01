// Kerberos support temporarily disabled due to licensing issues
// use crate::krb5::FileCredentialCache as CCache;

#[cfg(feature = "on_behalf_of")]
use crate::confidential_client::{ClientCredential, ConfidentialClientApplication, OboToken};
#[cfg(feature = "on_behalf_of")]
use crate::error::MsalError;
use crate::serializer::{deserialize_obj, serialize_obj};
use crate::{
    AuthInit, AuthOption, BrokerClientApplication, DeviceAuthorizationResponse, EnrollAttrs,
    MFAAuthContinue, MfaMethodInfo, PublicClientApplication, UserToken,
};

use kanidm_hsm_crypto::provider::{BoxedDynTpm, SoftTpm};
use kanidm_hsm_crypto::structures::{
    LoadableMachineKey, LoadableMsDeviceEnrolmentKey, LoadableMsHelloKey, LoadableMsOapxbcRsaKey,
    SealedData, StorageKey,
};
#[cfg(feature = "tpm")]
use kanidm_hsm_crypto::tpm::TpmTss;
use kanidm_hsm_crypto::AuthValue;
use pastey::paste;
#[cfg(feature = "on_behalf_of")]
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use std::future::Future;
use std::str::FromStr;
use tokio::runtime::Runtime;
use tracing::{warn, Level};
use tracing_subscriber::FmtSubscriber;

macro_rules! to_pyerr {
    ($e:ident) => {
        PyException::new_err(format!("{:?}", $e))
    };
}

fn wait<F>(f: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    match Runtime::new() {
        Ok(runtime) => Ok(runtime.block_on(f)),
        Err(e) => Err(to_pyerr!(e)),
    }
}

macro_rules! general_py_err {
    ($e:expr) => {
        PyException::new_err($e)
    };
}

macro_rules! str_vec_ref {
    ($items:ident) => {
        $items.iter().map(|i| i.as_str()).collect()
    };
}

macro_rules! run_async {
    ($client:expr, $func:ident $(, $arg:expr)* $(,)?) => {{
        let future = $client.$func($($arg),*);
        wait(future)?.map_err(|e| to_pyerr!(e))?
    }}
}

#[cfg(feature = "on_behalf_of")]
create_exception!(himmelblau, OboInteractionRequiredError, PyException);

#[cfg(feature = "on_behalf_of")]
fn to_obo_pyerr(
    py: Python<'_>,
    error: crate::error::ErrorResponse,
    claims: Option<String>,
) -> PyErr {
    let py_err = PyErr::new::<OboInteractionRequiredError, _>(format!(
        "OBO interaction required: {} ({})",
        error.error, error.error_description
    ));
    let py_err_value = py_err.value(py);
    let _ = py_err_value.setattr("claims", claims);
    let _ = py_err_value.setattr("error", error.error);
    let _ = py_err_value.setattr("error_description", error.error_description);
    let _ = py_err_value.setattr("error_codes", error.error_codes);
    let _ = py_err_value.setattr("suberror", error.suberror);
    py_err
}

macro_rules! serialize_impl {
    ($type:ident, $inner:ident) => {
        paste! {
            #[pymethods]
            impl [<Py $type>] {
                fn to_bytes(&self) -> PyResult<Py<PyAny>> {
                    let bytes = serialize_obj(&self.$inner)
                        .map_err(|e| to_pyerr!(e))?;
                    Python::attach(|py| Ok(PyBytes::new(py, &bytes).into()))
                }

                #[classmethod]
                fn from_bytes(_cls: &Bound<'_, PyType>, bytes: &Bound<'_, PyBytes>) -> PyResult<Self> {
                    let obj: $type = deserialize_obj(bytes.as_bytes())
                        .map_err(|e| to_pyerr!(e))?;
                    Ok([<Py $type>] {
                        $inner: obj
                    })
                }
            }
        }
    };
}

#[pyclass(name = "LoadableMachineKey", module = "himmelblau", subclass)]
pub struct PyLoadableMachineKey {
    key: LoadableMachineKey,
}
serialize_impl!(LoadableMachineKey, key);

#[pyclass(name = "StorageKey", module = "himmelblau", subclass)]
pub struct PyStorageKey {
    key: StorageKey,
}

#[pyclass(name = "LoadableMsOapxbcRsaKey", module = "himmelblau", subclass)]
pub struct PyLoadableMsOapxbcRsaKey {
    key: LoadableMsOapxbcRsaKey,
}
serialize_impl!(LoadableMsOapxbcRsaKey, key);

#[pyclass(name = "LoadableMsHelloKey", module = "himmelblau", subclass)]
pub struct PyLoadableMsHelloKey {
    key: LoadableMsHelloKey,
}
serialize_impl!(LoadableMsHelloKey, key);

#[pyclass(name = "LoadableMsDeviceEnrolmentKey", module = "himmelblau", subclass)]
pub struct PyLoadableMsDeviceEnrolmentKey {
    key: LoadableMsDeviceEnrolmentKey,
}
serialize_impl!(LoadableMsDeviceEnrolmentKey, key);

#[pyclass(name = "DeviceAuthorizationResponse", module = "himmelblau", subclass)]
pub struct PyDeviceAuthorizationResponse {
    flow: DeviceAuthorizationResponse,
}

#[pyclass(name = "MfaMethodInfo", module = "himmelblau", subclass)]
pub struct PyMfaMethodInfo {
    info: MfaMethodInfo,
}

#[pymethods]
impl PyMfaMethodInfo {
    #[getter]
    fn get_auth_method_id(&self) -> PyResult<String> {
        Ok(self.info.auth_method_id.clone())
    }

    #[getter]
    fn get_display(&self) -> PyResult<String> {
        Ok(self.info.display.clone())
    }

    #[getter]
    fn get_is_default(&self) -> PyResult<bool> {
        Ok(self.info.is_default)
    }

    fn __repr__(&self) -> String {
        format!(
            "MfaMethodInfo(auth_method_id='{}', display='{}', is_default={})",
            self.info.auth_method_id, self.info.display, self.info.is_default
        )
    }

    fn __str__(&self) -> String {
        format!(
            "{} ({}{})",
            self.info.auth_method_id,
            self.info.display,
            if self.info.is_default {
                " - DEFAULT"
            } else {
                ""
            }
        )
    }
}

#[pyclass(name = "MFAAuthContinue", module = "himmelblau", subclass)]
pub struct PyMFAAuthContinue {
    flow: MFAAuthContinue,
}

#[pymethods]
impl PyMFAAuthContinue {
    #[getter]
    fn msg(&self) -> PyResult<Option<String>> {
        Ok(Some(self.flow.msg.clone()))
    }

    #[getter]
    fn mfa_method(&self) -> PyResult<String> {
        Ok(self
            .flow
            .mfa_methods
            .first()
            .cloned()
            .unwrap_or_else(String::new))
    }

    #[getter]
    fn polling_interval(&self) -> PyResult<u32> {
        self.flow
            .polling_interval
            .ok_or(general_py_err!("Polling interval not found!"))
    }

    #[getter]
    fn max_poll_attempts(&self) -> PyResult<u32> {
        self.flow
            .max_poll_attempts
            .ok_or(general_py_err!("Max poll attempts not found!"))
    }

    /// Get all available MFA methods as a list of method IDs
    fn get_available_mfa_methods(&self) -> PyResult<Vec<String>> {
        Ok(self.flow.get_available_mfa_methods())
    }

    /// Get detailed information about all available MFA methods
    fn get_mfa_method_details(&self) -> PyResult<Vec<PyMfaMethodInfo>> {
        let details = self.flow.get_mfa_method_details();
        Ok(details
            .into_iter()
            .map(|info| PyMfaMethodInfo { info })
            .collect())
    }

    fn has_mfa_method(&self, method_id: &str) -> PyResult<bool> {
        Ok(self.flow.has_mfa_method(method_id))
    }

    fn mfa_method_count(&self) -> PyResult<usize> {
        Ok(self.flow.mfa_method_count())
    }

    fn get_default_mfa_method(&self) -> PyResult<String> {
        self.flow
            .get_default_mfa_method_details()
            .map(|info| info.auth_method_id.clone())
            .ok_or_else(|| general_py_err!("No default MFA method found"))
    }

    /// Get detailed information about the default MFA method
    fn get_default_mfa_method_details(&self) -> PyResult<Option<PyMfaMethodInfo>> {
        Ok(self
            .flow
            .get_default_mfa_method_details()
            .map(|info| PyMfaMethodInfo { info }))
    }

    /// Get detailed information about a specific MFA method by ID
    fn get_mfa_method_by_id(&self, method_id: &str) -> PyResult<Option<PyMfaMethodInfo>> {
        Ok(self
            .flow
            .get_mfa_method_by_id(method_id)
            .map(|info| PyMfaMethodInfo { info }))
    }
}

#[pyclass(name = "UserToken", module = "himmelblau", subclass)]
pub struct PyUserToken {
    token: UserToken,
}

#[pymethods]
impl PyUserToken {
    #[getter]
    fn refresh_token(&self) -> PyResult<String> {
        Ok(self.token.refresh_token.clone())
    }

    #[getter]
    fn access_token(&self) -> PyResult<Option<String>> {
        Ok(self.token.access_token.clone())
    }

    #[getter]
    fn get_tenant_id(&self) -> PyResult<String> {
        self.token.tenant_id().map_err(|e| to_pyerr!(e))
    }

    #[getter]
    fn get_spn(&self) -> PyResult<String> {
        self.token.spn().map_err(|e| to_pyerr!(e))
    }

    #[getter]
    fn get_uuid(&self) -> PyResult<String> {
        match self.token.uuid() {
            Ok(uuid) => Ok(uuid.to_string()),
            Err(e) => Err(to_pyerr!(e)),
        }
    }

    #[getter]
    fn get_amr_mfa(&self) -> PyResult<bool> {
        self.token.amr_mfa().map_err(|e| to_pyerr!(e))
    }

    #[getter]
    fn get_prt(&self) -> PyResult<PySealedData> {
        match &self.token.prt {
            Some(prt) => Ok(PySealedData { data: prt.clone() }),
            None => Err(general_py_err!("PRT not found!")),
        }
    }
}

#[pyclass(name = "SealedData", module = "himmelblau", subclass)]
pub struct PySealedData {
    data: SealedData,
}
serialize_impl!(SealedData, data);

// Kerberos support temporarily disabled
// #[pyclass(name = "AsRep", module = "himmelblau", subclass)]
// pub struct PyAsRep {
//     msg: AsRep,
// }

// Kerberos support temporarily disabled
// #[pyclass(name = "TGT", module = "himmelblau", subclass)]
// pub struct PyTGT {
//     tgt: TGT,
// }
//
// #[pymethods]
// impl PyTGT {
//     #[getter]
//     fn get_message(&self) -> PyResult<PyAsRep> {
//         Ok(PyAsRep {
//             msg: self.tgt.message().map_err(|e| to_pyerr!(e))?,
//         })
//     }
//
//     #[getter]
//     fn get_realm(&self) -> PyResult<String> {
//         match &self.tgt.realm {
//             Some(realm) => Ok(realm.clone()),
//             None => Err(general_py_err!("Realm not found!")),
//         }
//     }
//
//     #[getter]
//     fn get_sn(&self) -> PyResult<String> {
//         match &self.tgt.sn {
//             Some(sn) => Ok(sn.clone()),
//             None => Err(general_py_err!("sn not found!")),
//         }
//     }
//
//     #[getter]
//     fn get_cn(&self) -> PyResult<String> {
//         match &self.tgt.cn {
//             Some(cn) => Ok(cn.clone()),
//             None => Err(general_py_err!("cn not found!")),
//         }
//     }
//
//     #[getter]
//     fn get_session_key_type(&self) -> PyResult<u32> {
//         Ok(self.tgt.session_key_type)
//     }
//
//     #[getter]
//     fn get_account_type(&self) -> PyResult<u32> {
//         Ok(self.tgt.account_type)
//     }
// }

// Kerberos support temporarily disabled
// #[pyclass(name = "AesKey", module = "himmelblau", subclass)]
// pub struct PyAesKey {
//     client_key: AesKey,
// }

// TPM hardware interfaces are inherently single-threaded and cannot be safely
// shared between threads. The unsendable attribute tells PyO3 this class
// should not be thread-safe, which is appropriate for hardware interfaces.
#[pyclass(name = "Tpm", module = "himmelblau", subclass, unsendable)]
pub struct PyBoxedDynTpm {
    tpm: BoxedDynTpm,
}

#[pymethods]
impl PyBoxedDynTpm {
    #[new]
    pub fn new(tcti_name: Option<&str>, _py: Python) -> PyResult<Self> {
        let tpm = match tcti_name {
            #[cfg(feature = "tpm")]
            Some(tcti_name) => match TpmTss::new(&tcti_name) {
                Ok(tpm_tss) => BoxedDynTpm::new(tpm_tss),
                Err(e) => to_pyerr!(e),
            },
            #[cfg(not(feature = "tpm"))]
            Some(_) => {
                warn!(
                    "{} not built with tpm feature. Hardware tpm request ignored.",
                    env!("CARGO_PKG_NAME")
                );
                BoxedDynTpm::new(SoftTpm::new())
            }
            None => BoxedDynTpm::new(SoftTpm::new()),
        };
        Ok(PyBoxedDynTpm { tpm })
    }

    pub fn machine_key_create(
        &mut self,
        auth_value: &str,
        _py: Python,
    ) -> PyResult<PyLoadableMachineKey> {
        let auth_value = AuthValue::from_str(auth_value).map_err(|e| to_pyerr!(e))?;
        Ok(PyLoadableMachineKey {
            key: self
                .tpm
                .root_storage_key_create(&auth_value)
                .map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn machine_key_load(
        &mut self,
        auth_value: &str,
        exported_key: &PyLoadableMachineKey,
        _py: Python,
    ) -> PyResult<PyStorageKey> {
        let auth_value = AuthValue::from_str(auth_value).map_err(|e| to_pyerr!(e))?;
        Ok(PyStorageKey {
            key: self
                .tpm
                .root_storage_key_load(&auth_value, &exported_key.key)
                .map_err(|e| to_pyerr!(e))?,
        })
    }
}

#[pyfunction]
pub fn auth_value_generate() -> PyResult<String> {
    AuthValue::generate().map_err(|e| to_pyerr!(e))
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub enum PyAuthOption {
    Fido,
    Passwordless,
    PasswordlessFido,
    PasswordlessSecurityKey,
    PasswordlessQrBluetooth,
    NoDAGFallback,
}

impl From<PyAuthOption> for AuthOption {
    fn from(opt: PyAuthOption) -> Self {
        match opt {
            PyAuthOption::Fido => AuthOption::Fido,
            PyAuthOption::Passwordless => AuthOption::Passwordless,
            PyAuthOption::PasswordlessFido => AuthOption::PasswordlessFido,
            PyAuthOption::PasswordlessSecurityKey => AuthOption::PasswordlessSecurityKey,
            PyAuthOption::PasswordlessQrBluetooth => AuthOption::PasswordlessQrBluetooth,
            PyAuthOption::NoDAGFallback => AuthOption::NoDAGFallback,
        }
    }
}

#[pyclass]
pub struct PyAuthInit {
    auth_init: AuthInit,
}

#[pymethods]
impl PyAuthInit {
    pub fn exists(&self) -> bool {
        #[allow(deprecated)]
        self.auth_init.exists()
    }
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub enum TracingLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl From<TracingLevel> for Level {
    fn from(level: TracingLevel) -> Self {
        match level {
            TracingLevel::ERROR => Level::ERROR,
            TracingLevel::WARN => Level::WARN,
            TracingLevel::INFO => Level::INFO,
            TracingLevel::DEBUG => Level::DEBUG,
            TracingLevel::TRACE => Level::TRACE,
        }
    }
}

#[pyfunction]
pub fn set_global_tracing_level(level: TracingLevel) -> PyResult<()> {
    let level: Level = level.into();
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| to_pyerr!(e))?;
    Ok(())
}

#[pyclass(name = "EnrollAttrs", module = "himmelblau", subclass)]
pub struct PyEnrollAttrs {
    attrs: EnrollAttrs,
}

#[pymethods]
impl PyEnrollAttrs {
    #[new]
    pub fn new(
        target_domain: String,
        device_display_name: Option<String>,
        device_type: Option<String>,
        join_type: Option<u32>,
        os_version: Option<String>,
    ) -> PyResult<Self> {
        Ok(PyEnrollAttrs {
            attrs: EnrollAttrs::new(
                target_domain,
                device_display_name,
                device_type,
                join_type,
                os_version,
            )
            .map_err(|e| to_pyerr!(e))?,
        })
    }
}

#[pyclass(name = "PublicClientApplication", module = "himmelblau", subclass)]
pub struct PyPublicClientApplication {
    client: PublicClientApplication,
}

#[pymethods]
impl PyPublicClientApplication {
    #[new]
    pub fn new(client_id: &str, authority: Option<&str>) -> PyResult<Self> {
        Ok(PyPublicClientApplication {
            client: PublicClientApplication::new(
                client_id,
                authority,
                #[cfg(feature = "set_timeout")]
                std::time::Duration::from_secs(3),
                #[cfg(feature = "ipvers")]
                &[crate::IpVersion::V4, crate::IpVersion::V6],
            )
            .map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn check_user_exists(&self, username: &str) -> PyResult<PyAuthInit> {
        let auth_init = run_async!(self.client, check_user_exists, username, None, &[]);
        Ok(PyAuthInit { auth_init })
    }

    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned types
    #[pyo3(signature = (username, password, scopes, auth_init, mfa_method=None))]
    pub fn initiate_acquire_token_by_mfa_flow(
        &self,
        username: &str,
        password: Option<&str>,
        scopes: Vec<String>,
        auth_init: Option<&PyAuthInit>,
        mfa_method: Option<&str>,
    ) -> PyResult<PyMFAAuthContinue> {
        let scopes_ref: Vec<&str> = str_vec_ref!(scopes);
        let rust_auth_init = auth_init.map(|a| a.auth_init.clone());
        #[cfg(not(feature = "mfa_method_selection"))]
        let _ = mfa_method;
        #[cfg(not(feature = "mfa_method_selection"))]
        let flow = run_async!(
            self.client,
            initiate_acquire_token_by_mfa_flow,
            username,
            password,
            scopes_ref,
            None, // resource
            &[],  // options
            rust_auth_init
        );
        #[cfg(feature = "mfa_method_selection")]
        let flow = run_async!(
            self.client,
            initiate_acquire_token_by_mfa_flow,
            username,
            password,
            scopes_ref,
            None, // resource
            &[],  // options
            rust_auth_init,
            mfa_method
        );
        Ok(PyMFAAuthContinue { flow })
    }

    pub fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        flow: &mut PyMFAAuthContinue,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
    ) -> PyResult<PyUserToken> {
        let token = run_async!(
            self.client,
            acquire_token_by_mfa_flow,
            username,
            auth_data,
            poll_attempt,
            &mut flow.flow
        );
        Ok(PyUserToken { token })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<String>,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                acquire_token_by_username_password,
                username,
                password,
                str_vec_ref!(scopes)
            ),
        })
    }
}

#[pyclass(name = "BrokerClientApplication", module = "himmelblau", subclass)]
pub struct PyBrokerClientApplication {
    client: BrokerClientApplication,
}

#[pymethods]
impl PyBrokerClientApplication {
    #[new]
    pub fn new(
        authority: Option<&str>,
        client_id: Option<&str>,
        transport_key: Option<&PyLoadableMsOapxbcRsaKey>,
        cert_key: Option<&PyLoadableMsDeviceEnrolmentKey>,
    ) -> PyResult<Self> {
        Ok(PyBrokerClientApplication {
            client: BrokerClientApplication::new(
                authority,
                client_id,
                transport_key.map(|k| k.key.clone()),
                cert_key.map(|k| k.key.clone()),
                #[cfg(feature = "set_timeout")]
                std::time::Duration::from_secs(3),
                #[cfg(feature = "ipvers")]
                &[crate::IpVersion::V4, crate::IpVersion::V6],
            )
            .map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn enroll_device(
        &mut self,
        refresh_token: &str,
        attrs: &PyEnrollAttrs,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<(
        PyLoadableMsOapxbcRsaKey,
        PyLoadableMsDeviceEnrolmentKey,
        String,
    )> {
        let (transport_key, cert_key, device_id) = run_async!(
            self.client,
            enroll_device,
            refresh_token,
            attrs.attrs.clone(),
            &mut tpm.tpm,
            &machine_key.key,
        );
        Ok((
            PyLoadableMsOapxbcRsaKey { key: transport_key },
            PyLoadableMsDeviceEnrolmentKey { key: cert_key },
            device_id,
        ))
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        request_resource: Option<String>,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                acquire_token_by_username_password,
                username,
                password,
                str_vec_ref!(scopes),
                request_resource,
                None, // on_behalf_of_client_id
                &mut tpm.tpm,
                &machine_key.key,
            ),
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        request_resource: Option<String>,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                acquire_token_by_refresh_token,
                refresh_token,
                str_vec_ref!(scopes),
                request_resource,
                None, // on_behalf_of_client_id
                &mut tpm.tpm,
                &machine_key.key,
            ),
        })
    }

    pub fn acquire_token_by_username_password_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                acquire_token_by_username_password_for_device_enrollment,
                username,
                password
            ),
        })
    }

    pub fn initiate_device_flow_for_device_enrollment(
        &self,
    ) -> PyResult<PyDeviceAuthorizationResponse> {
        Ok(PyDeviceAuthorizationResponse {
            flow: run_async!(self.client, initiate_device_flow_for_device_enrollment,),
        })
    }

    pub fn acquire_token_by_device_flow(
        &self,
        flow: &PyDeviceAuthorizationResponse,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(self.client, acquire_token_by_device_flow, flow.flow.clone(),),
        })
    }

    pub fn check_user_exists(&self, username: &str) -> PyResult<PyAuthInit> {
        let auth_init = run_async!(self.client, check_user_exists, username, &[]);
        Ok(PyAuthInit { auth_init })
    }

    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned types
    #[pyo3(signature = (username, password, options, auth_init, selected_method=None))]
    pub fn initiate_acquire_token_by_mfa_flow_for_device_enrollment(
        &self,
        username: &str,
        password: Option<&str>,
        options: Vec<PyAuthOption>,
        auth_init: Option<&PyAuthInit>,
        selected_method: Option<&str>,
    ) -> PyResult<PyMFAAuthContinue> {
        let rust_options: Vec<AuthOption> = options.into_iter().map(|o| o.into()).collect();
        let rust_auth_init = auth_init.map(|a| a.auth_init.clone());

        #[cfg(not(feature = "mfa_method_selection"))]
        let _ = selected_method;
        #[cfg(not(feature = "mfa_method_selection"))]
        let flow = run_async!(
            self.client,
            initiate_acquire_token_by_mfa_flow_for_device_enrollment,
            username,
            password,
            &rust_options,
            rust_auth_init,
        );

        #[cfg(feature = "mfa_method_selection")]
        let flow = run_async!(
            self.client,
            initiate_acquire_token_by_mfa_flow_for_device_enrollment,
            username,
            password,
            &rust_options,
            rust_auth_init,
            selected_method,
        );

        Ok(PyMFAAuthContinue { flow })
    }

    pub fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        flow: &mut PyMFAAuthContinue,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
    ) -> PyResult<PyUserToken> {
        let token = run_async!(
            self.client,
            acquire_token_by_mfa_flow,
            username,
            auth_data,
            poll_attempt,
            &mut flow.flow,
        );
        Ok(PyUserToken { token })
    }

    pub fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                self.client,
                acquire_user_prt_by_username_password,
                username,
                password,
                &mut tpm.tpm,
                &machine_key.key,
            ),
        })
    }

    pub fn acquire_user_prt_by_refresh_token(
        &self,
        refresh_token: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                self.client,
                acquire_user_prt_by_refresh_token,
                refresh_token,
                &mut tpm.tpm,
                &machine_key.key,
            ),
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn exchange_prt_for_access_token(
        &self,
        sealed_prt: &PySealedData,
        scope: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        request_resource: Option<String>,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                exchange_prt_for_access_token,
                &sealed_prt.data,
                str_vec_ref!(scope),
                request_resource,
                None, // on_behalf_of_client_id
                &mut tpm.tpm,
                &machine_key.key,
                #[cfg(feature = "redirect_uri")]
                None,
                #[cfg(feature = "pop_support")]
                None,
            ),
        })
    }

    #[cfg(feature = "pop_support")]
    #[allow(clippy::needless_pass_by_value)]
    pub fn exchange_prt_for_access_token_pop(
        &self,
        sealed_prt: &PySealedData,
        scope: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        request_resource: Option<String>,
        req_cnf: Option<&str>,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                exchange_prt_for_access_token,
                &sealed_prt.data,
                str_vec_ref!(scope),
                request_resource,
                &mut tpm.tpm,
                &machine_key.key,
                #[cfg(feature = "redirect_uri")]
                None,
                req_cnf,
            ),
        })
    }

    pub fn exchange_prt_for_prt(
        &self,
        sealed_prt: &PySealedData,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        request_tgt: bool,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                self.client,
                exchange_prt_for_prt,
                &sealed_prt.data,
                &mut tpm.tpm,
                &machine_key.key,
                request_tgt,
            ),
        })
    }

    pub fn provision_hello_for_business_key(
        &self,
        token: &PyUserToken,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        pin: &str,
    ) -> PyResult<PyLoadableMsHelloKey> {
        Ok(PyLoadableMsHelloKey {
            key: run_async!(
                self.client,
                provision_hello_for_business_key,
                &token.token,
                &mut tpm.tpm,
                &machine_key.key,
                pin,
            ),
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_token_by_hello_for_business_key(
        &self,
        username: &str,
        key: &PyLoadableMsHelloKey,
        scopes: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        pin: &str,
        request_resource: Option<String>,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                self.client,
                acquire_token_by_hello_for_business_key,
                username,
                &key.key,
                str_vec_ref!(scopes),
                request_resource,
                None, // on_behalf_of_client_id
                &mut tpm.tpm,
                &machine_key.key,
                pin,
            ),
        })
    }

    pub fn acquire_user_prt_by_hello_for_business_key(
        &self,
        username: &str,
        key: &PyLoadableMsHelloKey,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
        pin: &str,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                self.client,
                acquire_user_prt_by_hello_for_business_key,
                username,
                &key.key,
                &mut tpm.tpm,
                &machine_key.key,
                pin,
            ),
        })
    }

    pub fn acquire_prt_sso_cookie(
        &self,
        prt: &PySealedData,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<String> {
        Ok(run_async!(
            self.client,
            acquire_prt_sso_cookie,
            &prt.data,
            &mut tpm.tpm,
            &machine_key.key,
        ))
    }

    pub fn store_cloud_tgt(
        &self,
        sealed_prt: &PySealedData,
        filename: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<()> {
        self.client
            .store_cloud_tgt(&sealed_prt.data, filename, &mut tpm.tpm, &machine_key.key)
            .map_err(|e| to_pyerr!(e))
    }

    pub fn store_ad_tgt(
        &self,
        sealed_prt: &PySealedData,
        filename: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<()> {
        self.client
            .store_ad_tgt(&sealed_prt.data, filename, &mut tpm.tpm, &machine_key.key)
            .map_err(|e| to_pyerr!(e))
    }

    pub fn unseal_prt_kerberos_top_level_names(
        &self,
        sealed_prt: &PySealedData,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyStorageKey,
    ) -> PyResult<String> {
        self.client
            .unseal_prt_kerberos_top_level_names(&sealed_prt.data, &mut tpm.tpm, &machine_key.key)
            .map_err(|e| to_pyerr!(e))
    }
}

// =========================================================================
// ConfidentialClientApplication (OBO flow)
// =========================================================================

#[cfg(feature = "on_behalf_of")]
#[pyclass(name = "OboToken", module = "himmelblau", subclass)]
pub struct PyOboToken {
    token: OboToken,
}

#[cfg(feature = "on_behalf_of")]
#[pymethods]
impl PyOboToken {
    #[getter]
    fn access_token(&self) -> PyResult<String> {
        Ok(self.token.access_token.clone())
    }

    #[getter]
    fn refresh_token(&self) -> PyResult<Option<String>> {
        Ok(self.token.refresh_token.clone())
    }

    #[getter]
    fn scope(&self) -> PyResult<Option<String>> {
        Ok(self.token.scope.clone())
    }

    #[getter]
    fn expires_in(&self) -> PyResult<u32> {
        Ok(self.token.expires_in)
    }

    #[getter]
    fn token_type(&self) -> PyResult<String> {
        Ok(self.token.token_type.clone())
    }

    #[getter]
    fn ext_expires_in(&self) -> PyResult<u32> {
        Ok(self.token.ext_expires_in)
    }
}

#[cfg(feature = "on_behalf_of")]
#[pyclass(
    name = "ConfidentialClientApplication",
    module = "himmelblau",
    subclass
)]
pub struct PyConfidentialClientApplication {
    client: ConfidentialClientApplication,
}

#[cfg(feature = "on_behalf_of")]
#[pymethods]
impl PyConfidentialClientApplication {
    /// Create a new ConfidentialClientApplication with a client secret.
    ///
    /// Args:
    ///     client_id: The application (client) ID registered in Entra ID.
    ///     authority: A URL identifying the token authority, e.g.
    ///         ``https://login.microsoftonline.com/<tenant>``.
    ///     client_secret: The client secret string.
    #[new]
    pub fn new(client_id: &str, authority: Option<&str>, client_secret: &str) -> PyResult<Self> {
        let credential = ClientCredential::from_secret(client_secret.to_string());
        Ok(PyConfidentialClientApplication {
            client: ConfidentialClientApplication::new(
                client_id,
                authority,
                credential,
                #[cfg(feature = "set_timeout")]
                std::time::Duration::from_secs(3),
                #[cfg(feature = "ipvers")]
                &[crate::IpVersion::V4, crate::IpVersion::V6],
            )
            .map_err(|e| to_pyerr!(e))?,
        })
    }

    /// Acquire a token using client credentials (client_credentials grant).
    ///
    /// Args:
    ///     scopes: List of scope strings for the target API.
    ///
    /// Returns:
    ///     A ClientToken (dict-like) with an ``access_token``.
    #[allow(clippy::needless_pass_by_value)]
    pub fn acquire_token_silent(&self, scopes: Vec<String>) -> PyResult<PyClientToken> {
        let scopes_ref: Vec<&str> = str_vec_ref!(scopes);
        let token = run_async!(self.client, acquire_token_silent, scopes_ref, None);
        Ok(PyClientToken { token })
    }

    /// Acquire a token on behalf of a user (OBO flow).
    ///
    /// Exchanges an incoming user access token for a new token targeting
    /// a downstream API, preserving the user's identity.
    ///
    /// Args:
    ///     user_assertion: The access token received by the middle-tier API.
    ///     scopes: List of scope strings for the downstream API.
    ///
    /// Returns:
    ///     An OboToken with ``access_token``, optional ``refresh_token``, etc.
    ///
    /// Raises:
    ///     OboInteractionRequiredError: Conditional Access claims challenge.
    ///     Exception: Other failures.
    #[allow(clippy::needless_pass_by_value)]
    pub fn acquire_token_on_behalf_of(
        &self,
        user_assertion: &str,
        scopes: Vec<String>,
    ) -> PyResult<PyOboToken> {
        let scopes_ref: Vec<&str> = str_vec_ref!(scopes);
        let future = self
            .client
            .acquire_token_on_behalf_of(user_assertion, scopes_ref, None);
        let result = wait(future)?;
        match result {
            Ok(token) => Ok(PyOboToken { token }),
            Err(MsalError::OboInteractionRequired { error, claims }) => {
                Python::attach(|py| Err(to_obo_pyerr(py, error, claims)))
            }
            Err(e) => Err(to_pyerr!(e)),
        }
    }
}

#[cfg(feature = "on_behalf_of")]
#[pyclass(name = "ClientToken", module = "himmelblau", subclass)]
pub struct PyClientToken {
    token: crate::confidential_client::ClientToken,
}

#[cfg(feature = "on_behalf_of")]
#[pymethods]
impl PyClientToken {
    #[getter]
    fn access_token(&self) -> PyResult<String> {
        Ok(self.token.access_token.clone())
    }

    #[getter]
    fn token_type(&self) -> PyResult<String> {
        Ok(self.token.token_type.clone())
    }

    #[getter]
    fn expires_in(&self) -> PyResult<u32> {
        Ok(self.token.expires_in)
    }

    #[getter]
    fn ext_expires_in(&self) -> PyResult<u32> {
        Ok(self.token.ext_expires_in)
    }

    #[getter]
    fn get_tenant_id(&self) -> PyResult<String> {
        self.token.tenant_id().map_err(|e| to_pyerr!(e))
    }
}

// Kerberos support temporarily disabled
// #[pyclass(name = "CCache", module = "himmelblau", subclass)]
// pub struct PyCCache {
//     ccache: CCache,
// }
//
// #[pymethods]
// impl PyCCache {
//     #[new]
//     pub fn new(tgt: &PyAsRep, client_key: &PyAesKey, _py: Python) -> PyResult<Self> {
//         Ok(PyCCache {
//             ccache: CCache::new(&tgt.msg, &client_key.client_key).map_err(|e| to_pyerr!(e))?,
//         })
//     }
//
//     pub fn save_keytab_file(&self, filename: &str) -> PyResult<()> {
//         self.ccache
//             .save_keytab_file(filename)
//             .map_err(|e| to_pyerr!(e))
//     }
// }

#[pymodule]
fn himmelblau(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPublicClientApplication>()?;
    m.add_class::<PyBrokerClientApplication>()?;
    #[cfg(feature = "on_behalf_of")]
    m.add_class::<PyConfidentialClientApplication>()?;
    m.add_class::<PyBoxedDynTpm>()?;
    m.add_class::<PyLoadableMachineKey>()?;
    m.add_class::<PyStorageKey>()?;
    m.add_class::<PyLoadableMsOapxbcRsaKey>()?;
    m.add_class::<PyLoadableMsHelloKey>()?;
    m.add_class::<PyEnrollAttrs>()?;
    m.add_class::<PyDeviceAuthorizationResponse>()?;
    m.add_class::<PyMfaMethodInfo>()?;
    m.add_class::<PyMFAAuthContinue>()?;
    m.add_class::<PyUserToken>()?;
    #[cfg(feature = "on_behalf_of")]
    m.add_class::<PyOboToken>()?;
    #[cfg(feature = "on_behalf_of")]
    m.add_class::<PyClientToken>()?;
    #[cfg(feature = "on_behalf_of")]
    m.add(
        "OboInteractionRequiredError",
        m.py().get_type::<OboInteractionRequiredError>(),
    )?;
    m.add_class::<PySealedData>()?;
    m.add_class::<PyAuthOption>()?;
    m.add_class::<PyAuthInit>()?;
    m.add_class::<TracingLevel>()?;
    // Kerberos support temporarily disabled
    // m.add_class::<PyAsRep>()?;
    // m.add_class::<PyAesKey>()?;
    // m.add_class::<PyTGT>()?;
    // m.add_class::<PyCCache>()?;
    m.add_function(wrap_pyfunction!(auth_value_generate, m)?)?;
    m.add_function(wrap_pyfunction!(set_global_tracing_level, m)?)?;
    Ok(())
}
