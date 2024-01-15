use ark_bn254::{Bn254, Fr as Bn254Fr, FrConfig};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ec::pairing::Pairing;
use ark_ff::{Fp, MontBackend};
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ark_std::rand::SeedableRng;
use num_bigint::BigInt;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use tokio::fs;

use crate::dto::GetCircuitFilesResponse;
use crate::utils::file::write_to_file;

use super::file::{find_latest_file_with_extension, read_file_as_string};
use super::serializer::{ark_de, ark_se};

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
    // // Read JSON string from file
    // let json_str = read_file_as_string(proof_filepath)?;

    // // Deserialize JSON string into Vec<u8>
    // let bytes: Vec<u8> = serde_json::from_str(&json_str)?;

    // // Use the ark_de function to deserialize Vec<u8> into Proof<E>
    // let proof: Proof<E> =
    //     ark_de(&mut serde_json::Deserializer::from_slice(&bytes))?;

    let proof_data = fs::read(&proof_filepath)
        .await
        .expect("Failed to read the proving key file");
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
