use crate::krb5::CCache;
use crate::serializer::{deserialize_obj, serialize_obj};
use crate::{
    AesKey, BrokerClientApplication, DeviceAuthorizationResponse, EnrollAttrs, MFAAuthContinue,
    UserToken, TGT,
};
use kanidm_hsm_crypto::soft::SoftTpm;
#[cfg(feature = "tpm")]
use kanidm_hsm_crypto::tpm::TpmTss;
use kanidm_hsm_crypto::{
    AuthValue, BoxedDynTpm, LoadableIdentityKey, LoadableMachineKey, LoadableMsOapxbcRsaKey,
    MachineKey, SealedData, Tpm,
};
use paste::paste;
use picky_krb::messages::AsRep;
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

fn wait<F>(py: Python, f: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    match Runtime::new() {
        Ok(runtime) => Ok(py.allow_threads(|| runtime.block_on(f))),
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
    ($py:ident, $client:expr, $func:ident $(, $arg:expr)* $(,)?) => {{
        let future = $client.$func($($arg),*);
        wait($py, future)?.map_err(|e| to_pyerr!(e))?
    }}
}

macro_rules! serialize_impl {
    ($type:ident, $inner:ident) => {
        paste! {
            #[pymethods]
            impl [<Py $type>] {
                fn to_bytes(&self, py: Python) -> PyResult<PyObject> {
                    let bytes = serialize_obj(&self.$inner)
                        .map_err(|e| to_pyerr!(e))?;
                    Ok(PyBytes::new_bound(py, &bytes).into())
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

#[pyclass(name = "MachineKey", module = "himmelblau", subclass)]
pub struct PyMachineKey {
    key: MachineKey,
}

#[pyclass(name = "LoadableMsOapxbcRsaKey", module = "himmelblau", subclass)]
pub struct PyLoadableMsOapxbcRsaKey {
    key: LoadableMsOapxbcRsaKey,
}
serialize_impl!(LoadableMsOapxbcRsaKey, key);

#[pyclass(name = "LoadableIdentityKey", module = "himmelblau", subclass)]
pub struct PyLoadableIdentityKey {
    key: LoadableIdentityKey,
}
serialize_impl!(LoadableIdentityKey, key);

#[pyclass(name = "DeviceAuthorizationResponse", module = "himmelblau", subclass)]
pub struct PyDeviceAuthorizationResponse {
    flow: DeviceAuthorizationResponse,
}

#[pyclass(name = "MFAAuthContinue", module = "himmelblau", subclass)]
pub struct PyMFAAuthContinue {
    flow: MFAAuthContinue,
}

#[pymethods]
impl PyMFAAuthContinue {
    #[getter]
    fn get_msg(&self) -> PyResult<String> {
        Ok(self.flow.msg.clone())
    }

    #[getter]
    fn get_mfa_method(&self) -> PyResult<String> {
        Ok(self.flow.mfa_method.clone())
    }

    #[getter]
    fn get_polling_interval(&self) -> PyResult<u32> {
        self.flow
            .polling_interval
            .ok_or(general_py_err!("Polling interval not found!"))
    }

    #[getter]
    fn get_max_poll_attempts(&self) -> PyResult<u32> {
        self.flow
            .max_poll_attempts
            .ok_or(general_py_err!("Max poll attempts not found!"))
    }
}

#[pyclass(name = "UserToken", module = "himmelblau", subclass)]
pub struct PyUserToken {
    token: UserToken,
}

#[pymethods]
impl PyUserToken {
    #[getter]
    fn get_refresh_token(&self) -> PyResult<String> {
        Ok(self.token.refresh_token.clone())
    }

    #[getter]
    fn get_access_token(&self) -> PyResult<String> {
        match &self.token.access_token {
            Some(access_token) => Ok(access_token.clone()),
            None => Err(general_py_err!("Access token not found!")),
        }
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

#[pyclass(name = "AsRep", module = "himmelblau", subclass)]
pub struct PyAsRep {
    msg: AsRep,
}

#[pyclass(name = "TGT", module = "himmelblau", subclass)]
pub struct PyTGT {
    tgt: TGT,
}

#[pymethods]
impl PyTGT {
    #[getter]
    fn get_message(&self) -> PyResult<PyAsRep> {
        Ok(PyAsRep {
            msg: self.tgt.message().map_err(|e| to_pyerr!(e))?,
        })
    }

    #[getter]
    fn get_realm(&self) -> PyResult<String> {
        match &self.tgt.realm {
            Some(realm) => Ok(realm.clone()),
            None => Err(general_py_err!("Realm not found!")),
        }
    }

    #[getter]
    fn get_sn(&self) -> PyResult<String> {
        match &self.tgt.sn {
            Some(sn) => Ok(sn.clone()),
            None => Err(general_py_err!("sn not found!")),
        }
    }

    #[getter]
    fn get_cn(&self) -> PyResult<String> {
        match &self.tgt.cn {
            Some(cn) => Ok(cn.clone()),
            None => Err(general_py_err!("cn not found!")),
        }
    }

    #[getter]
    fn get_session_key_type(&self) -> PyResult<u32> {
        Ok(self.tgt.session_key_type)
    }

    #[getter]
    fn get_account_type(&self) -> PyResult<u32> {
        Ok(self.tgt.account_type)
    }
}

#[pyclass(name = "AesKey", module = "himmelblau", subclass)]
pub struct PyAesKey {
    client_key: AesKey,
}

#[pyclass(name = "Tpm", module = "himmelblau", subclass)]
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
                .machine_key_create(&auth_value)
                .map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn machine_key_load(
        &mut self,
        auth_value: &str,
        exported_key: &PyLoadableMachineKey,
        _py: Python,
    ) -> PyResult<PyMachineKey> {
        let auth_value = AuthValue::from_str(auth_value).map_err(|e| to_pyerr!(e))?;
        Ok(PyMachineKey {
            key: self
                .tpm
                .machine_key_load(&auth_value, &exported_key.key)
                .map_err(|e| to_pyerr!(e))?,
        })
    }
}

#[pyfunction]
pub fn auth_value_generate() -> PyResult<String> {
    AuthValue::generate().map_err(|e| to_pyerr!(e))
}

#[pyclass]
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

#[pyclass(name = "BrokerClientApplication", module = "himmelblau", subclass)]
pub struct PyBrokerClientApplication {
    client: BrokerClientApplication,
}

#[pymethods]
impl PyBrokerClientApplication {
    #[new]
    pub fn new(
        authority: Option<&str>,
        transport_key: Option<&PyLoadableMsOapxbcRsaKey>,
        cert_key: Option<&PyLoadableIdentityKey>,
        _py: Python,
    ) -> PyResult<Self> {
        Ok(PyBrokerClientApplication {
            client: BrokerClientApplication::new(
                authority,
                transport_key.map(|k| k.key.clone()),
                cert_key.map(|k| k.key.clone()),
            )
            .map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn enroll_device(
        &mut self,
        refresh_token: &str,
        attrs: &PyEnrollAttrs,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
        py: Python,
    ) -> PyResult<(PyLoadableMsOapxbcRsaKey, PyLoadableIdentityKey, String)> {
        let (transport_key, cert_key, device_id) = run_async!(
            py,
            self.client,
            enroll_device,
            refresh_token,
            attrs.attrs.clone(),
            &mut tpm.tpm,
            &machine_key.key,
        );
        Ok((
            PyLoadableMsOapxbcRsaKey { key: transport_key },
            PyLoadableIdentityKey { key: cert_key },
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
        machine_key: &PyMachineKey,
        request_resource: Option<String>,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_username_password,
                username,
                password,
                str_vec_ref!(scopes),
                request_resource,
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
        machine_key: &PyMachineKey,
        request_resource: Option<String>,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_refresh_token,
                refresh_token,
                str_vec_ref!(scopes),
                request_resource,
                &mut tpm.tpm,
                &machine_key.key,
            ),
        })
    }

    pub fn acquire_token_by_username_password_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_username_password_for_device_enrollment,
                username,
                password
            ),
        })
    }

    pub fn initiate_device_flow_for_device_enrollment(
        &self,
        py: Python,
    ) -> PyResult<PyDeviceAuthorizationResponse> {
        Ok(PyDeviceAuthorizationResponse {
            flow: run_async!(py, self.client, initiate_device_flow_for_device_enrollment,),
        })
    }

    pub fn acquire_token_by_device_flow(
        &self,
        flow: &PyDeviceAuthorizationResponse,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_device_flow,
                flow.flow.clone(),
            ),
        })
    }

    pub fn check_user_exists(&self, username: &str, py: Python) -> PyResult<bool> {
        Ok(run_async!(py, self.client, check_user_exists, username,))
    }

    pub fn initiate_acquire_token_by_mfa_flow_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
        py: Python,
    ) -> PyResult<PyMFAAuthContinue> {
        Ok(PyMFAAuthContinue {
            flow: run_async!(
                py,
                self.client,
                initiate_acquire_token_by_mfa_flow_for_device_enrollment,
                username,
                password,
            ),
        })
    }

    pub fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        flow: &mut PyMFAAuthContinue,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_mfa_flow,
                username,
                auth_data,
                poll_attempt,
                &mut flow.flow,
            ),
        })
    }

    pub fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
        py: Python,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                py,
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
        machine_key: &PyMachineKey,
        py: Python,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                py,
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
        machine_key: &PyMachineKey,
        request_resource: Option<String>,
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
            ),
        })
    }

    pub fn exchange_prt_for_prt(
        &self,
        sealed_prt: &PySealedData,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
        request_tgt: bool,
        py: Python,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                py,
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
        machine_key: &PyMachineKey,
        pin: &str,
        py: Python,
    ) -> PyResult<PyLoadableIdentityKey> {
        Ok(PyLoadableIdentityKey {
            key: run_async!(
                py,
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
        key: &PyLoadableIdentityKey,
        scopes: Vec<String>,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
        pin: &str,
        request_resource: Option<String>,
        py: Python,
    ) -> PyResult<PyUserToken> {
        Ok(PyUserToken {
            token: run_async!(
                py,
                self.client,
                acquire_token_by_hello_for_business_key,
                username,
                &key.key,
                str_vec_ref!(scopes),
                request_resource,
                &mut tpm.tpm,
                &machine_key.key,
                pin,
            ),
        })
    }

    pub fn acquire_user_prt_by_hello_for_business_key(
        &self,
        username: &str,
        key: &PyLoadableIdentityKey,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
        pin: &str,
        py: Python,
    ) -> PyResult<PySealedData> {
        Ok(PySealedData {
            data: run_async!(
                py,
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
        machine_key: &PyMachineKey,
        py: Python,
    ) -> PyResult<String> {
        let jwt = run_async!(
            py,
            self.client,
            acquire_prt_sso_cookie,
            &prt.data,
            &mut tpm.tpm,
            &machine_key.key,
        )?;
        Ok(jwt)
    }

    pub fn store_cloud_tgt(
        &self,
        sealed_prt: &PySealedData,
        filename: &str,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
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
        machine_key: &PyMachineKey,
    ) -> PyResult<()> {
        self.client
            .store_ad_tgt(&sealed_prt.data, filename, &mut tpm.tpm, &machine_key.key)
            .map_err(|e| to_pyerr!(e))
    }

    pub fn unseal_prt_kerberos_top_level_names(
        &self,
        sealed_prt: &PySealedData,
        tpm: &mut PyBoxedDynTpm,
        machine_key: &PyMachineKey,
    ) -> PyResult<String> {
        self.client
            .unseal_prt_kerberos_top_level_names(&sealed_prt.data, &mut tpm.tpm, &machine_key.key)
            .map_err(|e| to_pyerr!(e))
    }
}

#[pyclass(name = "CCache", module = "himmelblau", subclass)]
pub struct PyCCache {
    ccache: CCache,
}

#[pymethods]
impl PyCCache {
    #[new]
    pub fn new(tgt: &PyAsRep, client_key: &PyAesKey, _py: Python) -> PyResult<Self> {
        Ok(PyCCache {
            ccache: CCache::new(&tgt.msg, &client_key.client_key).map_err(|e| to_pyerr!(e))?,
        })
    }

    pub fn save_keytab_file(&self, filename: &str) -> PyResult<()> {
        self.ccache
            .save_keytab_file(filename)
            .map_err(|e| to_pyerr!(e))
    }
}

#[pymodule]
fn himmelblau(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBrokerClientApplication>()?;
    m.add_class::<PyBoxedDynTpm>()?;
    m.add_class::<PyLoadableMachineKey>()?;
    m.add_class::<PyMachineKey>()?;
    m.add_class::<PyLoadableMsOapxbcRsaKey>()?;
    m.add_class::<PyLoadableIdentityKey>()?;
    m.add_class::<PyEnrollAttrs>()?;
    m.add_class::<PyDeviceAuthorizationResponse>()?;
    m.add_class::<PyMFAAuthContinue>()?;
    m.add_class::<PyUserToken>()?;
    m.add_class::<PySealedData>()?;
    m.add_class::<TracingLevel>()?;
    m.add_class::<PyAsRep>()?;
    m.add_class::<PyAesKey>()?;
    m.add_class::<PyCCache>()?;
    m.add_function(wrap_pyfunction!(auth_value_generate, m)?)?;
    m.add_function(wrap_pyfunction!(set_global_tracing_level, m)?)?;
    Ok(())
}
