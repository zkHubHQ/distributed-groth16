use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Validate,
};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct MyStruct {
    #[serde(deserialize_with = "deserialize_byte_array")]
    data: Vec<u8>,
}

fn deserialize_byte_array<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}

pub fn ark_se<S: serde::Serializer, A: CanonicalSerialize>(
    a: &A,
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

pub fn ark_de<'de, D: serde::de::Deserializer<'de>, A: CanonicalDeserialize>(
    data: D,
) -> Result<A, D::Error> {
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data).unwrap();
    let a =
        A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

pub fn ark_de_proof<
    'de,
    D: serde::de::Deserializer<'de>,
    A: CanonicalDeserialize,
>(
    data: Vec<u8>,
) -> Result<A, D::Error> {
    let a =
        A::deserialize_with_mode(data.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}
