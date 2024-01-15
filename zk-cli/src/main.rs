use ark_bn254::Bn254;
use ark_serialize::{CanonicalSerialize, Compress, Write};
use clap::{Parser, Subcommand};
use common::{
    dto::{
        CreateProofWithoutMpcRequest, CreateProofWithoutMpcResponse,
        GetCircuitFilesResponse, SaveCircuitRequest, SaveCircuitResponse,
        VerifyProofRequest, VerifyProofResponse,
    },
    utils::{
        arkworks_helpers::{parse_proof, parse_public_inputs},
        file::{read_file_as_vec, write_to_file},
        serializer::ark_se,
    },
};
use log::info;
use reqwest;
use reqwest::multipart;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct ZkCli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Saves circuit data
    Save {
        circuit_name: String,
        r1cs_filepath: String, // In practice, this would be a path to a file
        witness_generator_filepath: String, // In practice, this would be a path to a file
    },
    /// Generates a proof without MPC
    Prove {
        circuit_id: String,
        input_filepath: String, // In practice, this might be a more complex structure
        proof_output_filepath: String, // In practice, this would be a path to a file
    },
    /// Verifies a proof
    Verify {
        circuit_id: String,
        proof_filepath: String, // In practice, this would be a path to a file or a more complex structure
        public_inputs_filepath: String,
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
            r1cs_filepath,
            witness_generator_filepath,
        } => {
            // Asynchronously read the files and create multipart parts
            let r1cs_bytes = read_file_as_vec(&r1cs_filepath)?;
            let witness_generator_bytes =
                read_file_as_vec(&witness_generator_filepath)?;

            let r1cs_part =
                multipart::Part::bytes(r1cs_bytes).file_name("r1cs_file");
            let witness_generator_part =
                multipart::Part::bytes(witness_generator_bytes)
                    .file_name("witness_generator");

            // Create a multipart form
            let form = multipart::Form::new()
                .text("circuit_name", circuit_name)
                .part("r1cs_file", r1cs_part)
                .part("witness_generator", witness_generator_part);

            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:8000/save_circuit")
                .multipart(form)
                .send()
                .await?
                .json::<SaveCircuitResponse>()
                .await?;

            println!("Response: {:?}", res);
        }
        Commands::Prove {
            circuit_id,
            input_filepath,
            proof_output_filepath,
        } => {
            let input_bytes = read_file_as_vec(&input_filepath)?;
            let r1cs_part =
                multipart::Part::bytes(input_bytes).file_name("input_file");

            // Create a multipart form
            let form = multipart::Form::new()
                .text("circuit_id", circuit_id)
                .part("input_file", r1cs_part);

            let client = reqwest::Client::new();
            info!("Sending request to create proof without MPC");
            let res = client
                .post("http://localhost:8000/create_proof_without_mpc")
                .multipart(form)
                .send()
                .await?
                .json::<CreateProofWithoutMpcResponse>()
                .await?;

            info!("Proof created without MPC");
            info!("Response: {:?}", res);

            // Write the proof to a file
            // Serialize and save proving key
            let mut file = std::io::BufWriter::new(
                std::fs::File::create(&proof_output_filepath).unwrap(),
            );
            res.proof
                .serialize_with_mode(&mut file, Compress::Yes)
                .unwrap();
            file.flush().unwrap();

            info!("Proof written to file: {}", proof_output_filepath);

            println!("Response: {:?}", res);
        }
        Commands::Verify {
            circuit_id,
            proof_filepath,
            public_inputs_filepath,
        } => {
            let client = reqwest::Client::new();
            // print current working directory
            let cwd = std::env::current_dir().unwrap();
            println!("Current working directory: {}", cwd.display());
            let proof = parse_proof::<Bn254>(&proof_filepath).await?;
            let public_inputs = parse_public_inputs(&public_inputs_filepath)?;
            let res = client
                .post("http://localhost:8000/verify_proof")
                .json(&VerifyProofRequest {
                    circuit_id,
                    proof,
                    public_inputs,
                })
                .send()
                .await?
                .json::<VerifyProofResponse>()
                .await?;

            println!("Response: {:?}", res);
        }
    }

    Ok(())
}
