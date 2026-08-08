//! Minimal epee "portable binary storage" encoder/decoder.
//!
//! This is the serialization format used by Monero daemon binary RPC
//! endpoints such as `/getblocks.bin`, `/get_o_indexes.bin`,
//! `/get_outs.bin`, and `/get_output_distribution.bin`.

use color_eyre::Result;

/// The 9-byte portable-storage header (magic + format version).
pub const HEADER: [u8; 9] = [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];

// Type tags as defined by epee.
const TYPE_INT64: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT16: u8 = 3;
const TYPE_INT8: u8 = 4;
const TYPE_UINT64: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_UINT16: u8 = 7;
const TYPE_UINT8: u8 = 8;
const TYPE_DOUBLE: u8 = 9;
const TYPE_STRING: u8 = 10;
const TYPE_BOOL: u8 = 11;
const TYPE_OBJECT: u8 = 12;
const ARRAY_FLAG: u8 = 0x80;

/// An epee value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Length-prefixed byte string.
    String(Vec<u8>),
    /// Boolean.
    Bool(bool),
    /// A nested section (list of named entries).
    Object(Vec<(String, Value)>),
    /// A homogeneous array of u64 values.
    U64Array(Vec<u64>),
    /// A homogeneous array of byte strings.
    StringArray(Vec<Vec<u8>>),
    /// A homogeneous array of sections.
    ObjectArray(Vec<Vec<(String, Value)>>),
}

impl Value {
    /// Look up a named field within an entry list.
    pub fn get<'a>(entries: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
        entries.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Extract a u64 field from an entry list.
    pub fn get_u64(entries: &[(String, Value)], name: &str) -> Option<u64> {
        match Self::get(entries, name) {
            Some(Value::U64(v)) => Some(*v),
            _ => None,
        }
    }

    /// Extract a bool field from an entry list.
    pub fn get_bool(entries: &[(String, Value)], name: &str) -> Option<bool> {
        match Self::get(entries, name) {
            Some(Value::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    /// Extract a byte-string field from an entry list.
    pub fn get_bytes<'a>(entries: &'a [(String, Value)], name: &str) -> Option<&'a [u8]> {
        match Self::get(entries, name) {
            Some(Value::String(v)) => Some(v),
            _ => None,
        }
    }

    /// Extract a u64-array field from an entry list.
    pub fn get_u64_array<'a>(entries: &'a [(String, Value)], name: &str) -> Option<&'a [u64]> {
        match Self::get(entries, name) {
            Some(Value::U64Array(v)) => Some(v),
            _ => None,
        }
    }

    /// Extract an object-array field from an entry list.
    pub fn get_object_array<'a>(
        entries: &'a [(String, Value)],
        name: &str,
    ) -> Option<&'a [Vec<(String, Value)>]> {
        match Self::get(entries, name) {
            Some(Value::ObjectArray(v)) => Some(v),
            _ => None,
        }
    }
}

// ── Varint ────────────────────────────────────────────────────────────────────

/// Write an epee varint.
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 0x3F {
        out.push((value << 2) as u8);
    } else if value <= 0x3FFF {
        let v = (value << 2) | 1;
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if value <= 0x3FFF_FFFF {
        let v = (value << 2) | 2;
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        let v = (value << 2) | 3;
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn read_byte(cursor: &mut &[u8]) -> Result<u8> {
    if cursor.is_empty() {
        return Err(color_eyre::eyre::eyre!("epee: unexpected end of buffer"));
    }
    let byte = cursor[0];
    *cursor = &cursor[1..];
    Ok(byte)
}

fn read_n<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(color_eyre::eyre::eyre!(
            "epee: buffer too short (need {n} bytes, have {})",
            cursor.len()
        ));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

/// Read an epee varint from a cursor.
pub fn read_varint(cursor: &mut &[u8]) -> Result<u64> {
    let first = read_byte(cursor)?;
    let len = match first & 0b11 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    let mut value = u64::from(first >> 2);
    for i in 1..len {
        let byte = read_byte(cursor)?;
        value |= u64::from(byte) << (((i - 1) * 8) + 6);
    }
    Ok(value)
}

// ── Encoding ──────────────────────────────────────────────────────────────────

fn write_entry(out: &mut Vec<u8>, name: &str, value: &Value) {
    // The key length is a single raw byte (NOT a varint).
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    match value {
        Value::U64(v) => {
            out.push(TYPE_UINT64);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Value::String(bytes) => {
            out.push(TYPE_STRING);
            write_varint(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Bool(v) => {
            out.push(TYPE_BOOL);
            out.push(u8::from(*v));
        }
        Value::Object(entries) => {
            out.push(TYPE_OBJECT);
            write_section(out, entries);
        }
        Value::U64Array(items) => {
            out.push(TYPE_UINT64 | ARRAY_FLAG);
            write_varint(out, items.len() as u64);
            for item in items {
                out.extend_from_slice(&item.to_le_bytes());
            }
        }
        Value::StringArray(items) => {
            out.push(TYPE_STRING | ARRAY_FLAG);
            write_varint(out, items.len() as u64);
            for item in items {
                write_varint(out, item.len() as u64);
                out.extend_from_slice(item);
            }
        }
        Value::ObjectArray(items) => {
            out.push(TYPE_OBJECT | ARRAY_FLAG);
            write_varint(out, items.len() as u64);
            for entries in items {
                write_section(out, entries);
            }
        }
    }
}

fn write_section(out: &mut Vec<u8>, entries: &[(String, Value)]) {
    write_varint(out, entries.len() as u64);
    for (name, value) in entries {
        write_entry(out, name, value);
    }
}

/// Encode a complete epee request/response document (header + root section).
pub fn encode_document(entries: &[(String, Value)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&HEADER);
    write_section(&mut out, entries);
    out
}

// ── Decoding ──────────────────────────────────────────────────────────────────

fn read_fixed_u64(cursor: &mut &[u8]) -> Result<u64> {
    let bytes = read_n(cursor, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

fn read_string(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    let len = usize::try_from(read_varint(cursor)?)
        .map_err(|_| color_eyre::eyre::eyre!("epee: string length overflows usize"))?;
    Ok(read_n(cursor, len)?.to_vec())
}

fn read_section(cursor: &mut &[u8], depth: usize) -> Result<Vec<(String, Value)>> {
    if depth > 32 {
        return Err(color_eyre::eyre::eyre!("epee: section nesting too deep"));
    }
    let count = read_varint(cursor)?;
    let mut entries = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let name_len = read_byte(cursor)? as usize;
        let name = String::from_utf8_lossy(read_n(cursor, name_len)?).into_owned();
        let type_byte = read_byte(cursor)?;
        let is_array = type_byte & ARRAY_FLAG != 0;
        let kind = type_byte & !ARRAY_FLAG;

        let value = if is_array {
            let items = usize::try_from(read_varint(cursor)?)
                .map_err(|_| color_eyre::eyre::eyre!("epee: array length overflows usize"))?;
            match kind {
                TYPE_UINT64 => {
                    let mut vals = Vec::with_capacity(items.min(1 << 20));
                    for _ in 0..items {
                        vals.push(read_fixed_u64(cursor)?);
                    }
                    Value::U64Array(vals)
                }
                TYPE_STRING => {
                    let mut vals = Vec::with_capacity(items.min(1 << 20));
                    for _ in 0..items {
                        vals.push(read_string(cursor)?);
                    }
                    Value::StringArray(vals)
                }
                TYPE_OBJECT => {
                    let mut vals = Vec::with_capacity(items.min(1 << 20));
                    for _ in 0..items {
                        vals.push(read_section(cursor, depth + 1)?);
                    }
                    Value::ObjectArray(vals)
                }
                other => {
                    return Err(color_eyre::eyre::eyre!(
                        "epee: unsupported array element type {other}"
                    ));
                }
            }
        } else {
            match kind {
                TYPE_UINT64 => Value::U64(read_fixed_u64(cursor)?),
                TYPE_STRING => Value::String(read_string(cursor)?),
                TYPE_BOOL => Value::Bool(read_byte(cursor)? != 0),
                TYPE_OBJECT => Value::Object(read_section(cursor, depth + 1)?),
                // Scalar numeric types we don't model: skip their fixed-width bytes.
                TYPE_INT64 | TYPE_DOUBLE => {
                    read_n(cursor, 8)?;
                    continue;
                }
                TYPE_INT32 | TYPE_UINT32 => {
                    read_n(cursor, 4)?;
                    continue;
                }
                TYPE_INT16 | TYPE_UINT16 => {
                    read_n(cursor, 2)?;
                    continue;
                }
                TYPE_INT8 | TYPE_UINT8 => {
                    read_n(cursor, 1)?;
                    continue;
                }
                other => {
                    return Err(color_eyre::eyre::eyre!("epee: unsupported type {other}"));
                }
            }
        };
        entries.push((name, value));
    }
    Ok(entries)
}

/// Decode an epee document (validates the header, returns the root section).
pub fn decode_document(bytes: &[u8]) -> Result<Vec<(String, Value)>> {
    if bytes.len() < HEADER.len() || bytes[..HEADER.len()] != HEADER {
        return Err(color_eyre::eyre::eyre!("epee: invalid header"));
    }
    let mut cursor = &bytes[HEADER.len()..];
    let entries = read_section(&mut cursor, 0)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(entries: Vec<(String, Value)>) -> Vec<(String, Value)> {
        let encoded = encode_document(&entries);
        decode_document(&encoded).expect("decode failed")
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            0x3FFF,
            0x4000,
            0x3FFF_FFFF,
            0x4000_0000,
            u64::MAX >> 2,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut cursor = buf.as_slice();
            assert_eq!(read_varint(&mut cursor).unwrap(), v, "value {v}");
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn simple_fields_roundtrip() {
        let entries = vec![
            ("from_height".to_string(), Value::U64(3_000_000)),
            ("to_height".to_string(), Value::U64(3_100_000)),
            ("cumulative".to_string(), Value::Bool(true)),
            ("binary".to_string(), Value::Bool(false)),
        ];
        assert_eq!(roundtrip(entries.clone()), entries);
    }

    #[test]
    fn nested_object_array_roundtrip() {
        let entries = vec![(
            "outputs".to_string(),
            Value::ObjectArray(vec![
                vec![("index".to_string(), Value::U64(42))],
                vec![("index".to_string(), Value::U64(1337))],
            ]),
        )];
        assert_eq!(roundtrip(entries.clone()), entries);
    }

    #[test]
    fn strings_roundtrip() {
        let entries = vec![
            (
                "txid".to_string(),
                Value::String(b"\xde\xad\xbe\xef".to_vec()),
            ),
            (
                "blobs".to_string(),
                Value::StringArray(vec![vec![1, 2, 3], vec![4, 5]]),
            ),
        ];
        assert_eq!(roundtrip(entries.clone()), entries);
    }

    #[test]
    fn u64_array_roundtrip() {
        let entries = vec![(
            "distribution".to_string(),
            Value::U64Array(vec![1, 2, 3, 100, 10_000, u64::MAX]),
        )];
        assert_eq!(roundtrip(entries.clone()), entries);
    }

    #[test]
    fn rejects_bad_header() {
        assert!(decode_document(b"garbage").is_err());
    }

    #[test]
    fn get_outs_request_shape() {
        // The exact request body the daemon expects for /get_outs.bin.
        let body = encode_document(&[(
            "outputs".to_string(),
            Value::ObjectArray(vec![
                vec![("index".to_string(), Value::U64(100))],
                vec![("index".to_string(), Value::U64(200))],
            ]),
        )]);
        let decoded = decode_document(&body).unwrap();
        let outs = Value::get_object_array(&decoded, "outputs").unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(Value::get_u64(outs[0].as_slice(), "index"), Some(100));
        assert_eq!(Value::get_u64(outs[1].as_slice(), "index"), Some(200));
    }
}
