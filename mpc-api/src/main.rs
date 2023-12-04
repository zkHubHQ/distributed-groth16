use std::env;
use ark_bn254::{Bn254, Config};
use ark_ec::bn::Bn;
use ark_groth16::Proof;
use axum::{
    routing::get,
    Router, Json,
};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
struct VerifyProof {
    #[serde(rename = "circuitId")]
    circuit_id: String,
    #[serde(rename = "proofSystem")]
    proof_system: String,
    #[serde(rename = "curve")]
    curve: String,
    #[serde(rename = "proof")]
    proof: Proof<Bn254>,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
    #[serde(rename = "verifierKey")]
    verifier_key: String,
}

// verify the proof
async fn verify_proof(Json(proof): Json<VerifyProof>) -> Json<bool> {
    println!("circuitId: {}", proof.circuit_id);
    println!("proofSystem: {}", proof.proof_system);
    println!("curve: {}", proof.curve);
    println!("proof: {:?}", proof.proof);
    println!("publicInputs: {:?}", proof.public_inputs);
    println!("verifierKey: {}", proof.verifier_key);
    Json(true)
}

#[tokio::main]
async fn main() {
    // Get the port from the environment variable or use the default value of 8000
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());

    // build our application with a single route
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    // run our app with hyper, listening globally on the specified port
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    println!("Listening on port {}", port);
    axum::serve(listener, app).await.unwrap();
}