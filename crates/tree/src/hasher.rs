use jmt::SimpleHasher;
use serde::{ser::SerializeTupleStruct, Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct TreeHasher(sha2::Sha256);

impl SimpleHasher for TreeHasher {
    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

impl Serialize for TreeHasher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_tuple_struct("Sha256Wrapper", 0)?.end()
    }
}

impl<'de> Deserialize<'de> for TreeHasher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Sha256WrapperVisitor;

        impl<'de> serde::de::Visitor<'de> for Sha256WrapperVisitor {
            type Value = TreeHasher;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a Sha256Wrapper")
            }

            fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Ok(TreeHasher::default())
            }
        }

        deserializer.deserialize_tuple_struct("Sha256Wrapper", 0, Sha256WrapperVisitor)
    }
}
