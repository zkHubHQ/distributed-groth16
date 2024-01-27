use ark_ec::pairing::Pairing;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use std::error::Error;

use super::file::{read_file_as_string, read_file_as_vec};

use serde::Deserialize;
use serde_json::Value;

fn deserialize_as_vec_u64<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Number(num) => {
            if let Some(num) = num.as_u64() {
                Ok(vec![num])
            } else {
                Err(serde::de::Error::custom("Invalid number"))
            }
        }
        Value::Array(arr) => arr
            .into_iter()
            .map(|x| {
                x.as_u64().ok_or(serde::de::Error::custom("Invalid number"))
            })
            .collect(),
        _ => Err(serde::de::Error::custom(
            "Expected number or array of numbers",
        )),
    }
}

#[derive(Deserialize, Debug)]
pub struct InputVec(
    #[serde(deserialize_with = "deserialize_as_vec_u64")] pub Vec<u64>,
);

// The helper function for parsing
pub async fn parse_proof<E: Pairing>(
    proof_filepath: &str,
) -> Result<Proof<E>, Box<dyn Error>> {
    let proof_data = read_file_as_vec(&proof_filepath)?;
    let proof: Proof<E> = Proof::deserialize_with_mode(
        proof_data.as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .expect("Failed to deserialize proving key");

    Ok(proof)
}

// The helper function for parsing public inputs from a file as Vec<String>
pub fn parse_public_inputs(
    public_inputs_filepath: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Read JSON string from file
    let json_str = read_file_as_string(public_inputs_filepath)?;

    // Deserialize JSON string into Vec<String>
    let public_inputs: Vec<String> = serde_json::from_str(&json_str)?;

    Ok(public_inputs)
}
