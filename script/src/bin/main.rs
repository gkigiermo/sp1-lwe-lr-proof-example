//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use lwe_lr_lib::{linear_regression, PublicValuesLweStruct};
use simple_lwe::lwe::Lwe;
use simple_lwe::parameters::LweParameters;
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const LWE_LINEAR_REGRESSION: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "33")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the LWE encryption
    let plaintext_modulus: u32 = 8u32; // p
    let ciphertext_modulus: u32 = 128; // q
    let k: usize = 4; // This is the number of mask elements
    let std = 2.4123902401e-05;
    let params = LweParameters::new(plaintext_modulus, ciphertext_modulus, k, std);

    let mut ct = Lwe::new(&params);
    ct.import_ciphertext_from_file("data/encrypted_data");
    ct.import_secret_key_from_file("data/encrypted_data");
    ct.print_ciphertext();

    let mut ct_input: [u128; 5] = [0; 5];
    (0..5).for_each(|i| ct_input[i] = ct.ciphertext[i]);

    let mut expected_ct = linear_regression(&ct_input);
    expected_ct.import_secret_key_from_file("data/encrypted_data");
    let expected_value = expected_ct.decrypt(&params);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&ct_input);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(LWE_LINEAR_REGRESSION, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesLweStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesLweStruct {
            ct_input,
            ct_output,
        } = decoded;
        //let PublicValuesStruct { n, a, b } = decoded;

        (0..5).for_each(|i| println!("{} ", ct_output[i]));
        (0..5).for_each(|i| ct.ciphertext[i] = ct_output[i]);

        let decrypted_value = ct.decrypt(&params);
        println!("Decrypted value: {}", decrypted_value);

        assert_eq!(decrypted_value, expected_value);

        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(LWE_LINEAR_REGRESSION);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
