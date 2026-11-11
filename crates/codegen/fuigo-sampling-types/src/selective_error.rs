//! Selective envelope deserialization: unrelated values are consumed with IgnoredAny.
//! No serde_json::Value (or allocation proportional to an unrelated array) is built.
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

pub(crate) struct Envelope(pub Value);
impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Select(0, false).deserialize(d).map(Self)
    }
}
struct Select(usize, bool);
impl<'de> DeserializeSeed<'de> for Select {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.0 == 16 {
            IgnoredAny::deserialize(d)?;
            return Ok(Value::Null);
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Select {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an error envelope")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        // Envelopes are objects/strings. Arrays in a known scalar slot are invalid too.
        if !self.1 {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(Value::Null);
        }
        let mut found = None;
        while let Some(value) = seq.next_element_seed(Select(self.0 + 1, true))? {
            if crate::provider_error::walk(&value).is_some() {
                found = Some(value);
                break;
            }
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(found.map(|v| Value::Array(vec![v])).unwrap_or(Value::Null))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<Field>()? {
            if let Some(key) = key.0 {
                let value = map.next_value_seed(Select(self.0 + 1, self.1))?;
                out.insert(key.to_owned(), value);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(Value::Object(out))
    }
}
// Deserialize keys without allocating even when an unrelated key is very long.
struct Field(Option<&'static str>);
impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Key;
        impl Visitor<'_> for Key {
            type Value = Field;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an envelope key")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Field, E> {
                Ok(Field(
                    [
                        "error",
                        "response",
                        "state",
                        "type",
                        "code",
                        "provider_specific_fields",
                        "message",
                        "retry_after",
                        "resets_at",
                        "limit",
                        "detail",
                        "description",
                        "msg",
                        "param",
                        "field",
                        "error_code",
                    ]
                    .into_iter()
                    .find(|key| *key == s),
                ))
            }
        }
        d.deserialize_identifier(Key)
    }
}
pub(crate) fn from_slice(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Envelope>(bytes).ok().map(|v| v.0)
}

pub(crate) fn from_provider_str(text: &str) -> Option<Value> {
    let mut d = serde_json::Deserializer::from_str(text);
    let value = Select(0, true).deserialize(&mut d).ok()?;
    d.end().ok()?;
    Some(value)
}
