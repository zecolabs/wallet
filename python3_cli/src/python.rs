use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::{ed25519, keccak, keystore};

create_exception!(
    zecowallet._libcrypto,
    DecryptError,
    PyException,
    "Wrong password or keystore is corrupted/modified."
);
create_exception!(
    zecowallet._libcrypto,
    KeystoreError,
    PyException,
    "Invalid keystore format, unsupported version, or internal failure."
);

fn value_err(e: ed25519::LengthError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn keystore_err(e: keystore::KeystoreError) -> PyErr {
    match e {
        keystore::KeystoreError::Decrypt => DecryptError::new_err(e.to_string()),
        other => KeystoreError::new_err(other.to_string()),
    }
}

#[pyfunction]
#[pyo3(name = "keccak256")]
fn py_keccak256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new_bound(py, &keccak::keccak256(data))
}

#[pyfunction]
#[pyo3(name = "ed25519_public_key")]
fn py_ed25519_public_key<'py>(py: Python<'py>, seed: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let pk = ed25519::public_key(seed).map_err(value_err)?;
    Ok(PyBytes::new_bound(py, &pk))
}

#[pyfunction]
#[pyo3(name = "ed25519_sign")]
fn py_ed25519_sign<'py>(py: Python<'py>, seed: &[u8], msg: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sig = ed25519::sign(seed, msg).map_err(value_err)?;
    Ok(PyBytes::new_bound(py, &sig))
}

#[pyfunction]
#[pyo3(name = "ed25519_verify")]
fn py_ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> PyResult<bool> {
    ed25519::verify(public_key, msg, signature).map_err(value_err)
}

#[pyfunction]
#[pyo3(name = "keystore_encrypt", signature = (plaintext, password, address = ""))]
fn py_keystore_encrypt(py: Python<'_>, plaintext: &[u8], password: &str, address: &str) -> PyResult<String> {
    py.allow_threads(|| keystore::encrypt(plaintext, password, address))
        .map_err(keystore_err)
}

#[pyfunction]
#[pyo3(name = "keystore_decrypt")]
fn py_keystore_decrypt<'py>(py: Python<'py>, keystore_json: &str, password: &str) -> PyResult<Bound<'py, PyBytes>> {
    let pt = py
        .allow_threads(|| keystore::decrypt(keystore_json, password))
        .map_err(keystore_err)?;
    Ok(PyBytes::new_bound(py, &pt))
}

#[pymodule]
#[pyo3(name = "_libcrypto")]
fn libcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_keccak256, m)?)?;
    m.add_function(wrap_pyfunction!(py_ed25519_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(py_ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_keystore_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_keystore_decrypt, m)?)?;
    m.add("DecryptError", m.py().get_type_bound::<DecryptError>())?;
    m.add("KeystoreError", m.py().get_type_bound::<KeystoreError>())?;
    m.add("KEYSTORE_VERSION", keystore::VERSION)?;
    Ok(())
}
