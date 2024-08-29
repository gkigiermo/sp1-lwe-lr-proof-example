//! A simple program that takes a ciphertext array as input and performs a homomorphic linear regression on it.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use lwe_lr_lib::{linear_regression, PublicValuesLweStruct};
use simple_lwe::lwe::Lwe;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let input_array = sp1_zkvm::io::read::<[u128; 5]>();

    // Compute the linear regression using lwe ciphertexts.
    let ct_output: Lwe = linear_regression(&input_array);

    let output_array: [u128; 5] = [
        ct_output.ciphertext[0],
        ct_output.ciphertext[1],
        ct_output.ciphertext[2],
        ct_output.ciphertext[3],
        ct_output.ciphertext[4],
    ];
    // Encode the public values of the program.
    let bytes = PublicValuesLweStruct::abi_encode(&PublicValuesLweStruct {
        ct_input: input_array,
        ct_output: output_array,
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
