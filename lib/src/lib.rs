use alloy_sol_types::sol;
use simple_lwe::lwe::Lwe;
use simple_lwe::parameters::LweParameters;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }

    struct PublicValuesLweStruct {
        uint128[5] ct_input;
        uint128[5] ct_output;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

pub fn linear_regression(ciphertext: &[u128]) -> Lwe {
    // This are over simplified parameters probably not very secure
    let plaintext_modulus: u32 = 8u32; // p
    let ciphertext_modulus: u32 = 128; // q
    let k: usize = 4; // This is the number of mask elements
    let std = 2.412390240121573e-05;
    let params = LweParameters::new(plaintext_modulus, ciphertext_modulus, k, std);
    params.print();

    //Assuming a linear regression y = ax + b
    let a = 2u8;
    let b = 12u8;
    println!("Linear regression y = {}x + {} ", a, b);

    let mut ct = Lwe::new(&params);
    //brute force add the elements of the ciphertext, assuming 5 elements
    (0..5).for_each(|i| ct.ciphertext.push(ciphertext[i]));

    let mut trivial_ct = Lwe::new(&params);
    trivial_ct.encrypt_trivial(b, &params);

    ct.small_scalar_mult(a);
    ct.add(&trivial_ct);

    ct
}
