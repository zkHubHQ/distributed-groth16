use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{circom, CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInt;
use ark_groth16::{Groth16, Proof};
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer, Zero};
use dist_primitives::Opt;
use std::mem;
use std::sync::Arc;

use groth16::qap::qap;
use groth16::{ext_wit, qap};
use log::debug;
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};

use rand::SeedableRng;
use secret_sharing::pss::PackedSharingParams;

use groth16::proving_key::PackedProvingKeyShare;
use structopt::StructOpt;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

async fn dsha256<E, Net>(
    pp: &PackedSharingParams<E::ScalarField>,
    crs_share: &PackedProvingKeyShare<E>,
    qap_share: qap::PackedQAPShare<
        E::ScalarField,
        Radix2EvaluationDomain<E::ScalarField>,
    >,
    a_share: &[E::ScalarField],
    ax_share: &[E::ScalarField],
    net: &Net,
) -> (E::G1, E::G2, E::G1)
where
    E: Pairing,
    Net: MpcNet,
{
    let h_share = ext_wit::h(qap_share, pp, &net).await.unwrap();
    let msm_section = start_timer!(|| "MSM operations");
    // Compute msm while dropping the base vectors as they are not used again
    let compute_a = start_timer!(|| "Compute A");
    let pi_a_share = groth16::prove::A::<E> {
        L: Default::default(),
        N: Default::default(),
        r: E::ScalarField::zero(),
        pp,
        S: &crs_share.s,
        a: a_share,
    }
    .compute(net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_a);

    let compute_b = start_timer!(|| "Compute B");
    let pi_b_share: E::G2 = groth16::prove::B::<E> {
        Z: Default::default(),
        K: Default::default(),
        s: E::ScalarField::zero(),
        pp,
        V: &crs_share.v,
        a: a_share,
    }
    .compute(net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_b);

    let compute_c = start_timer!(|| "Compute C");
    let pi_c_share = groth16::prove::C::<E> {
        W: &crs_share.w,
        U: &crs_share.u,
        A: pi_a_share,
        M: Default::default(),
        r: E::ScalarField::zero(),
        s: E::ScalarField::zero(),
        pp,
        H: &crs_share.h,
        a: a_share,
        ax: ax_share,
        h: &h_share,
    }
    .compute(net)
    .await
    .unwrap();
    end_timer!(compute_c);

    end_timer!(msm_section);

    // Send pi_a_share, pi_b_share, pi_c_share to client
    (pi_a_share, pi_b_share, pi_c_share)
}

fn pack_from_witness<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    full_assignment: Vec<E::ScalarField>,
) -> Vec<Vec<E::ScalarField>> {
    let packed_assignments = cfg_chunks!(full_assignment, pp.l)
        .map(|chunk| {
            let secrets = if chunk.len() < pp.l {
                let mut secrets = chunk.to_vec();
                secrets.resize(pp.l, E::ScalarField::zero());
                secrets
            } else {
                chunk.to_vec()
            };
            pp.pack_from_public(secrets)
        })
        .collect::<Vec<_>>();

    cfg_into_iter!(0..pp.n)
        .map(|i| {
            cfg_into_iter!(0..packed_assignments.len())
                .map(|j| packed_assignments[j][i])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    // print current working directory
    let cwd = std::env::current_dir().unwrap();
    println!("Current working directory: {}", cwd.display());

    let cfg = CircomConfig::<Bn254>::new(
        "fixtures/sha256/sha256_js/sha256.wasm",
        "fixtures/sha256/sha256.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg.clone());
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    builder.push_input("a", 1);
    builder.push_input("b", 2);
    let circuit = builder.setup();
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(circuit, rng)
            .unwrap();

    let circom = builder.build().unwrap();
    let full_assignment = circom.witness.clone().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    let matrices = cs.to_matrices().unwrap();

    // New matrix without the inputs. Shadow the existing variables except full_assignment
    let mut builder2 = CircomBuilder::new(cfg.clone());
    let circuit2 = builder2.setup();
    let (pk2, vk2) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(
        circuit2, rng,
    )
    .unwrap();
    let circom2 = builder2.build().unwrap();
    let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
    circom2.generate_constraints(cs.clone()).unwrap();
    assert!(cs2.is_satisfied().unwrap());
    let matrices2 = cs2.to_matrices().unwrap();

    // print size of pk and vk
    println!("Size of pk: {}", mem::size_of_val(&pk2));
    println!("Size of vk: {}", mem::size_of_val(&vk2));
    println!("Size of matrices: {}", mem::size_of_val(&matrices));

    let size_of_montbackend = mem::size_of_val(&full_assignment[0]);

    let sizeof_matrix_a = mem::size_of_val(
        &matrices.a.iter().map(|row| row.len()).sum::<usize>(),
    );
    let sizeof_matrix_b = mem::size_of_val(
        &matrices.b.iter().map(|row| row.len()).sum::<usize>(),
    );
    let sizeof_matrix_c = mem::size_of_val(
        &matrices.c.iter().map(|row| row.len()).sum::<usize>(),
    );

    // Print the matrix
    println!("Matrix A len: {:?}", matrices.a.len());
    println!("Matrix B len: {:?}", matrices.b.len());
    println!("Matrix C len: {:?}", matrices.c.len());

    // full assignment length
    println!("Full assignment len: {:?}", full_assignment.len());

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    println!("Number of inputs: {}", num_inputs);
    println!("Number of constraints: {}", num_constraints);

    let num_inputs2 = matrices2.num_instance_variables;
    let num_constraints2 = matrices2.num_constraints;

    println!("Number of inputs2: {}", num_inputs2);
    println!("Number of constraints2: {}", num_constraints2);

    let r = Bn254Fr::zero();
    let s = Bn254Fr::zero();

    debug!("------------");
    debug!("Start creating proof without MPC");
    // measure time to create proof without MPC
    let arkworks_proof_time = start_timer!(|| "Arkworks Proof");
    let arkworks_proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment,
    ).unwrap();
    end_timer!(arkworks_proof_time);
    debug!("End creating proof without MPC");

    println!("Arkworks Proof: {:?}", arkworks_proof);
    // time taken to create proof without MPC
    println!(
        "Time taken to create proof without MPC: {:?}",
        arkworks_proof_time.time.elapsed()
    );

    let pvk = ark_groth16::verifier::prepare_verifying_key(&vk);
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &[BigInt!(
            "72587776472194017031617589674261467945970986113287823188107011979"
        )
        .into()],
        &arkworks_proof,
    )
    .unwrap();

    assert!(verified, "Arkworks Proof verification failed!");
    let proof = Proof::<Bn254> {
        a: arkworks_proof.a,
        b: arkworks_proof.b,
        c: arkworks_proof.c,
    };
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &[BigInt!(
            "72587776472194017031617589674261467945970986113287823188107011979"
        )
        .into()],
        &proof,
    )
    .unwrap();
    assert!(verified, "Proof verification failed!");
}
