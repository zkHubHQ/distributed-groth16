use axum::extract::DefaultBodyLimit;
use axum::extract::Path as AxumPath;
use bincode::de;
use common::dto::CreateProofWithoutMpcRequest;
use common::dto::CreateProofWithoutMpcResponse;
use common::dto::CustomError;
use common::dto::GetCircuitFilesRequest;
use common::dto::GetCircuitFilesResponse;
use common::dto::SaveCircuitRequest;
use common::dto::SaveCircuitResponse;
use num_bigint::BigInt;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
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
use common::dto::VerifyProofRequest;
use common::dto::VerifyProofResponse;
use common::utils::arkworks_helpers::InputVec;
use common::utils::file::find_latest_file_with_extension;
use log::{debug, error, info};
use rand::SeedableRng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::collections::HashMap;
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
                request.r1cs_filepath = bytes.to_vec();
            }
            "witness_generator" => {
                let bytes = field.bytes().await.unwrap();
                request.witness_generator_filepath = bytes.to_vec();
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
        "circuit_{}_{}",
        request.circuit_name,
        chrono::Utc::now().timestamp_millis()
    );

    info!("Saving circuit with id: {}", circuit_id);
    info!("Received circuit with name: {}", request.circuit_name);

    // Save the r1cs file and witness generator file
    save_file(
        &circuit_id,
        &format!("{}.r1cs", request.circuit_name),
        &request.r1cs_filepath,
    )
    .await
    .map_err(|_err| {
        CustomError::new(
            std::io::ErrorKind::Other,
            "Error occurred while reading the r1cs file",
        )
    })?;
    save_file(
        &circuit_id,
        &format!("{}.wasm", request.circuit_name),
        &request.witness_generator_filepath,
    )
    .await
    .map_err(|_err| {
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

    info!("Saving proving key to {}", pk_path);
    info!("Saving verifying key to {}", vk_path);

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

    info!("Saved circuit with id: {}", circuit_id);

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

    println!("Public inputs: {:?}", public_inputs);

    // Verify the proof
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &request.proof,
    )
    .unwrap();

    let time_taken = start.elapsed().as_millis() as i64;

    let verification_response = VerifyProofResponse {
        circuit_id: request.circuit_id,
        public_inputs: Some(request.public_inputs),
        verifier_key: None, // Serialized verifier key, if necessary
        proof: Some(request.proof), // Serialized proof, if necessary
        is_valid: verified,
        time_taken: Some(time_taken),
        remarks: Some("Verification completed".to_string()),
    };

    Json(verification_response)
}

async fn save_file(
    circuit_id: &str,
    file_name: &str,
    data: &[u8],
) -> Result<(), Error> {
    let file_path = Path::new(&circuit_id).join(file_name);

    // Create the directory if it doesn't exist
    if let Some(dir_path) = file_path.parent() {
        fs::create_dir_all(dir_path).await?;
    }

    let mut file = BufWriter::new(File::create(&file_path).await?);
    file.write_all(data).await?;
    Ok(())
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
    mut multipart: Multipart,
) -> Result<Json<CreateProofWithoutMpcResponse>, CustomError> {
    let start = Instant::now();

    let mut request = CreateProofWithoutMpcRequest::default();

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();

        match name.as_str() {
            "circuit_id" => {
                let bytes = field.bytes().await.unwrap();
                request.circuit_id = String::from_utf8(bytes.to_vec()).unwrap();
            }
            "input_file" => {
                let bytes = field.bytes().await.unwrap();
                request.input_file_str =
                    String::from_utf8(bytes.to_vec()).unwrap();
            }
            _ => {
                return Err(CustomError::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid field",
                ))
            }
        }
    }

    info!(
        "Starting to create proof without MPC for circuit_id: {}",
        request.circuit_id
    );

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

    info!("Proving key found, proceeding with reading and deserialization.");

    // Read and deserialize the proving key
    let pk_data = fs::read(&pk_path)
        .await
        .expect("Failed to read the proving key file");
    let pk: ProvingKey<Bn254> = ProvingKey::deserialize_with_mode(
        pk_data.as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .expect("Failed to deserialize proving key");

    info!("Proving key deserialized successfully.");

    let r = Bn254Fr::zero();
    let s = Bn254Fr::zero();

    // Directory path for r1cs and witness files
    let dir_path = format!("{}", &request.circuit_id);

    // Find the latest r1cs file asynchronously
    let r1cs_path = find_latest_file_with_extension(&dir_path, "r1cs")
        .await
        .unwrap();

    // Corresponding wtns file path (assuming it shares the same base name)
    let witness_path = r1cs_path.with_extension("wasm");

    // Log the paths
    info!("r1cs_path: {}", r1cs_path.display());
    info!("witness_path: {}", witness_path.display());

    // Create a CircomBuilder instance
    let cfg = CircomConfig::<Bn254>::new(&witness_path, &r1cs_path).unwrap();
    let mut builder = CircomBuilder::new(cfg);

    // Add the inputs from the input file
    let input_map: HashMap<String, InputVec> =
        serde_json::from_str(&request.input_file_str).unwrap();

    // Iterate over the HashMap and use push_input
    for (key, values) in input_map {
        for value in values.0 {
            builder.push_input(&key, BigInt::from(value));
        }
    }

    // Generate the circuit
    let circom = builder.build().unwrap();
    let full_assignment = circom.witness.clone().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    let matrices = cs.to_matrices().unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    // Log information about the circuit
    info!("Number of inputs: {}", num_inputs);
    info!("Number of constraints: {}", num_constraints);

    let arkworks_proof_time = start_timer!(|| "Arkworks Proof");
    // Generate the proof
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment,
    )
    .expect("Proof generation failed");
    end_timer!(arkworks_proof_time);

    let time_taken = start.elapsed().as_millis() as i64;

    info!(
        "Proof created successfully for circuit_id {} in {} ms.",
        request.circuit_id, time_taken
    );

    // Create response
    let response = CreateProofWithoutMpcResponse {
        circuit_id: request.circuit_id,
        proof,
        time_taken,
    };

    Ok(Json(response))
}

/// Get r1cs and wasm file by circuit_id
/// Expects the r1cs and wasm files to be present in the filesystem
/// Returns the r1cs and wasm files
///
/// # Inputs
///
/// * `circuit_id` - the id of the circuit
///
/// # Returns
///
/// A Json object with the following fields:
///
/// * `r1cs_file` - the r1cs file (Multi-part file)
/// * `witness_generator` - the witness generator wasm file (Multi-part file)
///
async fn get_circuit_files(
    AxumPath(circuit_id): AxumPath<String>,
) -> Result<Json<GetCircuitFilesResponse>, CustomError> {
    let start = Instant::now();

    // Directory path for r1cs and witness files
    let dir_path = format!("{}", circuit_id);

    // Find the latest r1cs file asynchronously
    let r1cs_path = find_latest_file_with_extension(&dir_path, "r1cs")
        .await
        .unwrap();

    // Corresponding wasm file path (assuming it shares the same base name)
    let wasm_path = r1cs_path.with_extension("wasm");

    // Read the r1cs file
    let r1cs_file = fs::read(&r1cs_path)
        .await
        .expect("Failed to read the r1cs file");

    // Read the wasm file
    let wasm_file = fs::read(&wasm_path)
        .await
        .expect("Failed to read the wasm file");

    let time_taken = start.elapsed().as_millis() as i64;

    // Create response
    let response = GetCircuitFilesResponse {
        r1cs_file,
        witness_generator: wasm_file,
        time_taken,
    };

    Ok(Json(response))
}

#[tokio::main]
async fn main() {
    color_backtrace::install();
    // initialize the logger
    env_logger::init();

    // Get the port from the environment variable or use the default value of 8000
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/save_circuit", post(save_circuit))
        .route("/create_proof_without_mpc", post(create_proof_without_mpc))
        .route("/verify_proof", post(verify_proof))
        .route("/get_circuit_files/:circuit_id", get(get_circuit_files))
        .layer(DefaultBodyLimit::max(104857600)); // 100MB

    // run our app with hyper, listening globally on the specified port
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    println!("Listening on port {}", port);
    axum::serve(listener, app).await.unwrap();
}
