use clap::{Parser, Subcommand};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct ZkCli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Saves circuit data
    Save {
        circuit_name: String,
        r1cs_file: String, // In practice, this would be a path to a file
        witness_generator: String, // In practice, this would be a path to a file
    },
    /// Generates a proof without MPC
    Prove {
        circuit_id: String,
        full_assignment: Vec<String>, // In practice, this might be a more complex structure
    },
    /// Verifies a proof
    Verify {
        circuit_id: String,
        proof_system: String,
        curve: String,
        proof: String, // In practice, this would be a path to a file or a more complex structure
        public_inputs: Vec<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct ApiResponse {
    // Structure this according to the expected response from your API
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = ZkCli::parse();

    match cli.command {
        Commands::Save {
            circuit_name,
            r1cs_file,
            witness_generator,
        } => {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:8000/save_circuit")
                .json(&json!({
                    "circuit_name": circuit_name,
                    "r1cs_file": r1cs_file,
                    "witness_generator": witness_generator,
                }))
                .send()
                .await?
                .json::<ApiResponse>()
                .await?;

            println!("Response: {:?}", res);
        }
        Commands::Prove {
            circuit_id,
            full_assignment,
        } => {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:8000/create_proof_without_mpc")
                .json(&json!({
                    "circuit_id": circuit_id,
                    "full_assignment": full_assignment,
                }))
                .send()
                .await?
                .json::<ApiResponse>()
                .await?;

            println!("Response: {:?}", res);
        }
        Commands::Verify {
            circuit_id,
            proof_system,
            curve,
            proof,
            public_inputs,
        } => {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:8000/verify_proof")
                .json(&json!({
                    "circuit_id": circuit_id,
                    "proof_system": proof_system,
                    "curve": curve,
                    "proof": proof,
                    "public_inputs": public_inputs,
                }))
                .send()
                .await?
                .json::<ApiResponse>()
                .await?;

            println!("Response: {:?}", res);
        }
    }

    Ok(())
}
