//! Complete proof serialization plus a field/hash payload audit.
//!
//! CBOR preserves the distinction between BN254's 32-byte byte strings and
//! BLAKE3's `[u8; 32]` arrays. Walk the entire serialized object, including
//! retained dynamic components; never inspect allocation capacities or keys.

use ciborium::Value;
use serde::{Serialize, de::DeserializeOwned};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    /// All BN254 values, including the Poseidon roots/digests counted below.
    pub field_elements: usize,
    pub blake3_hashes: usize,
    /// Subset of field_elements; do not add this again to payload_bytes.
    pub poseidon_hashes: usize,
    pub serialized_bytes: usize,
}

impl Metrics {
    pub fn payload_bytes(self) -> usize {
        32 * (self.field_elements + self.blake3_hashes)
    }

    pub fn overhead_bytes(self) -> usize {
        self.serialized_bytes - self.payload_bytes()
    }
}

pub struct EncodedProof {
    pub metrics: Metrics,
    pub bytes: Vec<u8>,
    /// Top-level components plus outer map/key framing, which sum to the total.
    pub components: Vec<(String, Metrics)>,
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn count(value: &Value, key: &str, metrics: &mut Metrics) -> Result<()> {
    match value {
        Value::Bytes(bytes) => {
            // p3-bn254 0.6.2 serializes every field element as 32 Montgomery
            // bytes. Reject a changed field representation instead of silently
            // reporting a misleading payload count.
            if bytes.len() != 32 {
                return Err(
                    format!("unexpected byte-string length at {key}: {}", bytes.len()).into(),
                );
            }
            metrics.field_elements += 1;
            metrics.poseidon_hashes += usize::from(matches!(key, "root" | "digest"));
        }
        Value::Array(items) if matches!(key, "cap" | "proof") => {
            // MerkleCap.cap and QueryOpening.proof are Vec<[u8; 32]> in this
            // concrete WHIR instantiation. Other integer arrays are metadata.
            for item in items {
                let Value::Array(digest) = item else {
                    return Err(format!("unexpected Merkle digest representation at {key}").into());
                };
                if digest.len() != 32 || !digest.iter().all(|byte| {
                    matches!(byte, Value::Integer(n) if (0..=255).contains(&i128::from(*n)))
                }) {
                    return Err(format!("invalid 32-byte Merkle digest at {key}").into());
                }
                metrics.blake3_hashes += 1;
            }
        }
        Value::Array(items) => {
            for item in items {
                count(item, key, metrics)?;
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                let Value::Text(key) = key else {
                    return Err("non-text proof field name".into());
                };
                count(value, key, metrics)?;
            }
        }
        Value::Integer(_) | Value::Text(_) | Value::Null | Value::Bool(_) => {}
        _ => return Err("unsupported proof serialization value".into()),
    }
    Ok(())
}

pub fn encode(proof: &impl Serialize) -> Result<EncodedProof> {
    let bytes = serialize(proof)?;
    let value: Value = ciborium::de::from_reader(bytes.as_slice())?;
    let mut metrics = Metrics {
        serialized_bytes: bytes.len(),
        ..Metrics::default()
    };
    count(&value, "", &mut metrics)?;
    if metrics.payload_bytes() > bytes.len() {
        return Err("proof payload exceeds encoded proof size".into());
    }
    let Value::Map(entries) = value else {
        return Err("proof must be a named structure".into());
    };
    let mut components = Vec::new();
    let mut component_bytes = 0;
    for (key, value) in entries {
        let Value::Text(name) = key else {
            return Err("non-text proof field name".into());
        };
        let mut component = Metrics {
            serialized_bytes: serialize(&value)?.len(),
            ..Metrics::default()
        };
        count(&value, &name, &mut component)?;
        component_bytes += component.serialized_bytes;
        components.push((name, component));
    }
    components.push((
        "outer_framing".into(),
        Metrics {
            serialized_bytes: bytes
                .len()
                .checked_sub(component_bytes)
                .ok_or("invalid component size")?,
            ..Metrics::default()
        },
    ));
    Ok(EncodedProof {
        metrics,
        bytes,
        components,
    })
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut reader = bytes;
    let mut value: Value = ciborium::de::from_reader(&mut reader)?;
    if !reader.is_empty() {
        return Err("trailing bytes after proof".into());
    }
    // WHIR's internally tagged enum buffers fields through Serde's Content
    // type. That buffer cannot hand a byte string to Bn254's Vec<u8> visitor.
    // Normalize byte strings to equivalent byte sequences only for decoding;
    // the on-disk proof retains compact CBOR byte strings.
    fn normalize(value: &mut Value) {
        match value {
            Value::Bytes(bytes) => {
                *value = Value::Array(bytes.iter().map(|&b| Value::Integer(b.into())).collect());
            }
            Value::Array(items) => items.iter_mut().for_each(normalize),
            Value::Map(entries) => entries.iter_mut().for_each(|(_, v)| normalize(v)),
            _ => {}
        }
    }
    normalize(&mut value);
    Ok(value.deserialized()?)
}
