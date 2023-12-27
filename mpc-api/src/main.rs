mod utils;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
use ark_ff::BigInt;
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use ark_serialize::Validate;
use ark_serialize::Write;
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer, Zero};
use axum::http::request;
use axum::routing::post;
use axum::{
    extract::Multipart,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use log::{debug, error, info};
use rand::SeedableRng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::io::Error;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use std::{
    env,
    // fs::{self},
    path::Path,
    time::Instant,
};
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt; // for `write_all`
use tokio::io::BufWriter;
use utils::serializer::{ark_de, ark_se};

#[derive(Deserialize)]
struct VerifyProofRequest {
    #[serde(rename = "circuitId")]
    circuit_id: String,
    #[serde(rename = "proofSystem")]
    proof_system: String,
    #[serde(rename = "curve")]
    curve: String,
    #[serde(rename = "proof", deserialize_with = "ark_de")]
    proof: Proof<Bn254>,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
}

/// Response object for the `verifyProof` endpoint
#[derive(Serialize)]
struct VerifyProofResponse {
    #[serde(rename = "circuitId")]
    circuit_id: Option<String>,
    #[serde(rename = "proofSystem")]
    proof_system: Option<String>,
    #[serde(rename = "curve")]
    curve: Option<String>,
    #[serde(rename = "publicInputs")]
    public_inputs: Option<Vec<String>>,
    #[serde(rename = "verifierKey", serialize_with = "ark_se")]
    verifier_key: Option<PreparedVerifyingKey<Bn254>>,
    #[serde(rename = "proof", serialize_with = "ark_se")]
    proof: Option<Proof<Bn254>>,
    #[serde(rename = "isValid")]
    is_valid: bool,
    #[serde(rename = "timeTaken")]
    time_taken: Option<i64>,
    #[serde(rename = "remarks")]
    remarks: Option<String>,
}

impl Default for VerifyProofResponse {
    fn default() -> Self {
        Self {
            circuit_id: None,
            proof_system: None,
            curve: None,
            public_inputs: None,
            verifier_key: None,
            proof: None,
            is_valid: false,
            time_taken: None,
            remarks: None,
        }
    }
}

#[derive(Debug)]
struct SaveCircuitRequest {
    circuit_name: String,
    r1cs_file: Vec<u8>,
    witness_generator: Vec<u8>,
}

impl Default for SaveCircuitRequest {
    fn default() -> Self {
        Self {
            circuit_name: String::new(),
            r1cs_file: Vec::new(),
            witness_generator: Vec::new(),
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
#[derive(Serialize)]
struct SaveCircuitResponse {
    #[serde(rename = "circuitId")]
    circuit_id: String,
    #[serde(rename = "circuitName")]
    circuit_name: String,
    #[serde(rename = "timeTaken")]
    time_taken: i64,
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

#[derive(Deserialize)]
struct CreateProofWithoutMpcRequest {
    #[serde(rename = "circuitId")]
    circuit_id: String,
    #[serde(rename = "fullAssignment", deserialize_with = "ark_de")]
    full_assignment: Vec<Bn254Fr>,
}

#[derive(Serialize)]
struct CreateProofWithoutMpcResponse {
    #[serde(rename = "circuitId")]
    circuit_id: String,
    #[serde(rename = "proof", serialize_with = "ark_se")]
    proof: Proof<Bn254>,
    #[serde(rename = "timeTaken")]
    time_taken: i64,
}

#[derive(Debug)]
struct CustomError {
    kind: ErrorKind,
    message: String,
}

impl CustomError {
    fn new(kind: ErrorKind, message: &str) -> Self {
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

/// Save a circuit
///
/// # Inputs
///
/// * `circuit_name` - the name of the circuit
/// * `r1cs_file` - the r1cs file (Multi-part file)
/// * `witness_generator` - the witness generator wasm file (Multi-part file)
///
/// # Returns
///
/// A Json object with the following fields:
///
/// * `circuit_id` - the id of the circuit
/// * `circuit_name` - the name of the circuit
async fn save_circuit(
    mut multipart: Multipart,
) -> Result<Json<SaveCircuitResponse>, CustomError> {
    let start = Instant::now();

    let mut request = SaveCircuitRequest::default();

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();

        match name.as_str() {
            "circuit_name" => {
                let bytes = field.bytes().await.unwrap();
                request.circuit_name =
                    String::from_utf8(bytes.to_vec()).unwrap();
            }
            "r1cs_file" => {
                let bytes = field.bytes().await.unwrap();
                request.r1cs_file = bytes.to_vec();
            }
            "witness_generator" => {
                let bytes = field.bytes().await.unwrap();
                request.witness_generator = bytes.to_vec();
            }
            _ => {
                return Err(CustomError::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid field",
                ))
            }
        }
    }

    let circuit_id = format!(
        "{}_{}",
        request.circuit_name,
        chrono::Utc::now().timestamp_millis()
    );

    // Save the r1cs file and witness generator file
    save_file(
        &circuit_id,
        &format!("{}.r1cs", request.circuit_name),
        &request.r1cs_file,
    )
    .await
    .map_err(|err| {
        CustomError::new(
            std::io::ErrorKind::Other,
            "Error occurred while reading the r1cs file",
        )
    })?;
    save_file(
        &circuit_id,
        &format!("{}.wasm", request.circuit_name),
        &request.witness_generator,
    )
    .await
    .map_err(|err| {
        CustomError::new(
            std::io::ErrorKind::Other,
            "Error occurred while reading the wasm file",
        )
    })?;

    // Assuming the paths where the r1cs and wasm files are saved
    let r1cs_path = format!("{}/{}.r1cs", &circuit_id, request.circuit_name);
    let wasm_path = format!("{}/{}.wasm", &circuit_id, request.circuit_name);

    // Generate CRS Params
    let cfg = CircomConfig::<Bn254>::new(&wasm_path, &r1cs_path).unwrap();
    let mut builder = CircomBuilder::new(cfg);
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    let circuit = builder.setup();
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(circuit, rng)
            .unwrap();

    // Save CRS params to the filesystem
    let pk_path = format!("{}/proving_key.bin", &circuit_id);
    let vk_path = format!("{}/verifying_key.bin", &circuit_id);

    // Serialize and save proving key
    let mut file =
        std::io::BufWriter::new(std::fs::File::create(&pk_path).unwrap());
    pk.serialize_with_mode(&mut file, Compress::Yes).unwrap();
    file.flush().unwrap();

    // Serialize and save verifying key
    let mut file =
        std::io::BufWriter::new(std::fs::File::create(&vk_path).unwrap());
    vk.serialize_with_mode(&mut file, Compress::Yes).unwrap();
    file.flush().unwrap();

    // Return data in response
    let time_taken = start.elapsed().as_millis() as i64;
    let response = SaveCircuitResponse {
        circuit_id: circuit_id.clone(),
        circuit_name: request.circuit_name,
        time_taken,
    };

    Ok(Json(response))
}

/// verify the proof
async fn verify_proof(
    Json(request): Json<VerifyProofRequest>,
) -> Json<VerifyProofResponse> {
    let start = Instant::now();
    info!("Received proof for circuit_id: {}", request.circuit_id);

    // Load the verifying key from the filesystem
    let vk_path = format!("{}/verifying_key.bin", request.circuit_id);
    if !Path::new(&vk_path).exists() {
        error!(
            "Verifying key for circuit_id {} not found.",
            request.circuit_id
        );
        return Json(VerifyProofResponse::default());
    }

    // Read and deserialize the verifying key
    let vk_data = fs::read(&vk_path)
        .await
        .expect("Failed to read the verifying key file");
    let vk: VerifyingKey<Bn254> = VerifyingKey::deserialize_with_mode(
        vk_data.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .expect("Failed to deserialize verifying key");
    let pvk = ark_groth16::verifier::prepare_verifying_key(&vk);

    // Convert public inputs to the appropriate format
    let public_inputs: Vec<_> = request
        .public_inputs
        .iter()
        .map(|input| {
            <Bn<ark_bn254::Config> as Pairing>::ScalarField::from_str(input)
                .map_err(|_| "Failed to parse input string")
                .unwrap()
        })
        .collect();

    // Verify the proof
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &request.proof,
    )
    .is_ok();

    let time_taken = start.elapsed().as_millis() as i64;

    Json(VerifyProofResponse {
        circuit_id: Some(request.circuit_id),
        proof_system: Some(request.proof_system),
        curve: Some(request.curve),
        public_inputs: Some(request.public_inputs),
        verifier_key: None, // Serialized verifier key, if necessary
        proof: Some(request.proof), // Serialized proof, if necessary
        is_valid: verified,
        time_taken: Some(time_taken),
        remarks: Some("Verification completed".to_string()),
    })
}

async fn save_file(
    circuit_id: &str,
    file_name: &str,
    data: &[u8],
) -> Result<(), Error> {
    let file_path = Path::new(&circuit_id).join(file_name);
    let mut file = BufWriter::new(File::create(&file_path).await?);

    file.write_all(data).await?;
    Ok(())
}

// Additional helper function to find the latest file with a specific extension
async fn find_latest_file_with_extension(
    dir_path: &str,
    extension: &str,
) -> Result<PathBuf, Error> {
    let mut latest: Option<(SystemTime, PathBuf)> = None;

    let mut entries = fs::read_dir(dir_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
            let metadata = fs::metadata(&path).await?;
            let modified = metadata.modified()?;
            if latest
                .clone()
                .map(|(time, _)| modified > time)
                .unwrap_or(true)
            {
                latest = Some((modified, path));
            }
        }
    }

    latest.map(|(_, path)| path).ok_or_else(|| {
        Error::new(
            std::io::ErrorKind::NotFound,
            format!("No .{} files found in directory {}", extension, dir_path),
        )
    })
}

/// Create a Groth16 proof without MPC
/// Expects the proving key to be present in the filesystem
///
/// # Inputs
///
/// * `circuit_id` - the id of the circuit
/// * `full_assignment` - the full assignment (Multi-part file)
///
/// # Returns
///
/// A Json object with the following fields:
///
/// * `circuit_id` - the id of the circuit
/// * `proof` - the proof (Multi-part file)
/// * `time_taken` - the time taken to generate the proof
/// * `remarks` - any remarks
async fn create_proof_without_mpc(
    Json(request): Json<CreateProofWithoutMpcRequest>,
) -> Result<Json<CreateProofWithoutMpcResponse>, CustomError> {
    let start = Instant::now();

    // Load the proving key from the filesystem
    let pk_path = format!("{}/proving_key.bin", request.circuit_id);
    if !Path::new(&pk_path).exists() {
        error!(
            "Proving key for circuit_id {} not found.",
            request.circuit_id
        );
        return Err(CustomError::new(
            std::io::ErrorKind::NotFound,
            "Proving key not found",
        ));
    }

    // Read and deserialize the proving key
    let pk_data = fs::read(&pk_path)
        .await
        .expect("Failed to read the proving key file");
    let pk: ProvingKey<Bn254> = ProvingKey::deserialize_with_mode(
        pk_data.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .expect("Failed to deserialize proving key");

    let r = Bn254Fr::zero();
    let s = Bn254Fr::zero();

    // Directory path for r1cs and witness files
    let dir_path = format!("{}", &request.circuit_id);

    // Find the latest r1cs file asynchronously
    let r1cs_path = find_latest_file_with_extension(&dir_path, "r1cs")
        .await
        .unwrap();

    // Corresponding wtns file path (assuming it shares the same base name)
    let witness_path = r1cs_path.with_extension("wtns");

    // Create a CircomBuilder instance
    let cfg = CircomConfig::<Bn254>::new(&witness_path, &r1cs_path).unwrap();
    let mut builder = CircomBuilder::new(cfg);

    // Generate the circuit
    let circuit = builder.build().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    let matrices = cs.to_matrices().unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let arkworks_proof_time = start_timer!(|| "Arkworks Proof");
    // Generate the proof
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &request.full_assignment,
    )
    .expect("Proof generation failed");
    end_timer!(arkworks_proof_time);
    debug!("End creating proof without MPC");

    let time_taken = start.elapsed().as_millis() as i64;

    // Create response
    let response = CreateProofWithoutMpcResponse {
        circuit_id: request.circuit_id,
        proof,
        time_taken,
    };

    Ok(Json(response))
}

#[tokio::main]
async fn main() {
    // initialize the logger
    // env_logger::init();

    // Get the port from the environment variable or use the default value of 8000
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/save_circuit", post(save_circuit))
        .route("/create_proof_without_mpc", post(create_proof_without_mpc))
        .route("/verify_proof", post(verify_proof));

    // run our app with hyper, listening globally on the specified port
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    println!("Listening on port {}", port);
    axum::serve(listener, app).await.unwrap();
}
