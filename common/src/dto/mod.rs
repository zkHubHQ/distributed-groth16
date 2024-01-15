// use crate::utils;

use std::{collections::HashMap, io::ErrorKind};

use crate::utils::{
    arkworks_helpers::InputVec,
    serializer::{ark_de, ark_se},
};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use axum::{http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
pub struct VerifyProofRequest {
    #[serde(rename = "circuitId")]
    pub circuit_id: String,
    #[serde(
        rename = "proof",
        serialize_with = "ark_se",
        deserialize_with = "ark_de"
    )]
    pub proof: Proof<Bn254>,
    #[serde(rename = "publicInputs")]
    pub public_inputs: Vec<String>,
}

/// Response object for the `verifyProof` endpoint
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyProofResponse {
    #[serde(rename = "circuitId")]
    pub circuit_id: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: Option<Vec<String>>,
    #[serde(
        rename = "verifierKey",
        serialize_with = "ark_se",
        deserialize_with = "ark_de"
    )]
    pub verifier_key: Option<PreparedVerifyingKey<Bn254>>,
    #[serde(
        rename = "proof",
        serialize_with = "ark_se",
        deserialize_with = "ark_de"
    )]
    pub proof: Option<Proof<Bn254>>,
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    #[serde(rename = "timeTaken")]
    pub time_taken: Option<i64>,
    #[serde(rename = "remarks")]
    pub remarks: Option<String>,
}

impl Default for VerifyProofResponse {
    fn default() -> Self {
        Self {
            circuit_id: String::new(),
            public_inputs: None,
            verifier_key: None,
            proof: None,
            is_valid: false,
            time_taken: None,
            remarks: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SaveCircuitRequest {
    pub circuit_name: String,
    pub r1cs_filepath: Vec<u8>,
    pub witness_generator_filepath: Vec<u8>,
}

impl Default for SaveCircuitRequest {
    fn default() -> Self {
        Self {
            circuit_name: String::new(),
            r1cs_filepath: Vec::new(),
            witness_generator_filepath: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct CreateProofWithoutMpcRequest {
    pub circuit_id: String,
    pub input_file_str: String,
}

impl Default for CreateProofWithoutMpcRequest {
    fn default() -> Self {
        Self {
            circuit_id: String::new(),
            input_file_str: String::new(),
        }
    }
}

#[derive(Serialize)]
struct CrsParams {
    #[serde(rename = "provingKey", serialize_with = "ark_se")]
    proving_key: Option<ProvingKey<Bn254>>,
    #[serde(rename = "verifyingKey", serialize_with = "ark_se")]
    verifying_key: Option<VerifyingKey<Bn254>>,
}

/// Response object for the `saveCircuit` endpoint
#[derive(Serialize, Deserialize, Debug)]
pub struct SaveCircuitResponse {
    #[serde(rename = "circuitId")]
    pub circuit_id: String,
    #[serde(rename = "circuitName")]
    pub circuit_name: String,
    #[serde(rename = "timeTaken")]
    pub time_taken: i64,
}

impl Default for SaveCircuitResponse {
    fn default() -> Self {
        Self {
            circuit_id: String::new(),
            circuit_name: String::new(),
            time_taken: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateProofWithoutMpcResponse {
    #[serde(rename = "circuitId")]
    pub circuit_id: String,
    #[serde(
        rename = "proof",
        serialize_with = "ark_se",
        deserialize_with = "ark_de"
    )]
    pub proof: Proof<Bn254>,
    #[serde(rename = "timeTaken")]
    pub time_taken: i64,
}

#[derive(Debug)]
pub struct CustomError {
    kind: ErrorKind,
    message: String,
}

impl CustomError {
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind: kind,
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {} - {}", self.kind, self.message)
    }
}

impl std::error::Error for CustomError {}

impl IntoResponse for CustomError {
    fn into_response(self) -> axum::response::Response {
        let body = axum::Json(json!({ "error": self.message }));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetCircuitFilesRequest {
    #[serde(rename = "circuitId")]
    pub circuit_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetCircuitFilesResponse {
    #[serde(rename = "r1csFile")]
    pub r1cs_file: Vec<u8>,
    #[serde(rename = "witnessGenerator")]
    pub witness_generator: Vec<u8>,
    #[serde(rename = "timeTaken")]
    pub time_taken: i64,
}
