use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};

pub(crate) fn serialize_obj<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    to_vec(value)
}

pub(crate) fn deserialize_obj<'a, T: Deserialize<'a>>(
    value: &'a [u8],
) -> Result<T, serde_json::Error> {
    from_slice(value)
}
