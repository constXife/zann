//! Duplicate-free JSON validation with an explicit node/member budget. No IO or defaults.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{cell::Cell, collections::BTreeSet, fmt, rc::Rc};
use zeroize::Zeroize;

#[derive(Clone)]
struct DuplicateFreeJson {
    nodes: Rc<Cell<usize>>,
    max_nodes: usize,
}

impl DuplicateFreeJson {
    fn new(max_nodes: usize) -> Self {
        Self {
            nodes: Rc::new(Cell::new(0)),
            max_nodes,
        }
    }

    fn consume<E: de::Error>(&self) -> Result<(), E> {
        let next = self.nodes.get().checked_add(1).ok_or_else(|| {
            de::Error::custom("JSON node/member budget exceeds addressable range")
        })?;
        if next > self.max_nodes {
            return Err(de::Error::custom("JSON node/member budget exceeded"));
        }
        self.nodes.set(next);
        Ok(())
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ZeroizingJsonKey(String);

impl Drop for ZeroizingJsonKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> DeserializeSeed<'de> for DuplicateFreeJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.consume()?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateFreeJson {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(self.clone())?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.consume()?;
            if !seen.insert(ZeroizingJsonKey(key)) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(self.clone())?;
        }
        Ok(())
    }
}

pub fn validate_json_shape(bytes: &[u8], max_nodes: usize) -> Result<(), serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateFreeJson::new(max_nodes).deserialize(&mut deserializer)?;
    deserializer.end()
}
