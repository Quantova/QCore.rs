// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A generated master seed must be real entropy, thirty two bytes, and it must derive a valid

#![cfg(feature = "client")]

use qcore::{account_address, generate_seed, valid_address};

#[test]
fn a_generated_seed_is_thirty_two_bytes_derives_a_valid_address_and_is_not_constant() {
    let first = generate_seed().expect("generate a seed");
    let second = generate_seed().expect("generate a seed");
    assert_eq!(first.len(), 32, "a master seed is thirty two bytes");
    assert_ne!(first, second, "two generated seeds must differ");
    let address = account_address(&first, 0);
    assert!(valid_address(&address), "a generated seed derives a valid q1 address");
}
