// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The JavaScript core is generated over this Rust core, so the two must agree byte for byte on

use qcore::{account_address, chain_id_from_name, sign_call, LOCAL_CHAIN_ID, SEED_LEN};
use qtv_tx::{sign, Body, Call, TESTNET_CHAIN_ID};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The seed the cross language conformance vectors share.
fn shared_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    seed
}

#[test]
fn the_derived_addresses_match_the_qcore_js_vector() {
    let seed = shared_seed();
    assert_eq!(
        account_address(&seed, 7),
        "Q133C9CYVYZNQ7X25H0JJWUDHU8U5G3DN7CQC4J64LFTRSUH66ZNCQWDRA8R"
    );
    assert_eq!(
        account_address(&seed, 8),
        "Q1H2PLGDKK73HPS8PM4EQT5NL7MV8K9ENUMCDQC4V0GKDEJC3FTYAS70UVL8"
    );
}

#[test]
fn the_transfer_body_reproduces_the_qcore_js_vector() {
    let seed = shared_seed();
    let target = account_address(&seed, 8);
    let signed = sign_call(
        &seed,
        7,
        &target,
        vec![0xde, 0xad, 0xbe, 0xef],
        3,
        21_000,
        1_000_000,
        LOCAL_CHAIN_ID,
    );
    let body_bytes = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef000000000000000098ba0ce08f27d0be";
    assert!(
        hex(&signed.tx_bytes).starts_with(body_bytes),
        "the signed body prefix is the frozen QCore.js transfer body"
    );
    assert_eq!(
        signed.tx_id,
        "QTX1YK67DZ8VNL9KLDM7SAKMRM0C34XZKTRTNGRXHKGN962GW285ULTSK7GQCM"
    );
}

#[test]
fn the_payable_transaction_reproduces_the_qcore_js_vector() {
    let seed = shared_seed();
    let sender = qtv_account::derive(&seed, 7);
    let target = account_address(&seed, 8);
    let call = Call::new(target, vec![0xde, 0xad, 0xbe, 0xef]);
    let body = Body::with_context(sender.address(), 3, 21_000, 1_000_000, call, 250_000, TESTNET_CHAIN_ID);
    let wrapper = sign(&sender, &body);
    assert!(qtv_tx::verify(&wrapper, sender.public_key()));
    assert_eq!(
        wrapper.id(),
        "QTX1MZP3CC4JCWG77XJUWZUCUFAAZL205P8AXJRUZSK5NEXPXPY74FUS2K2N7U"
    );
}

#[test]
fn the_target_case_never_moves_the_signed_bytes() {
    let seed = shared_seed();
    let upper = account_address(&seed, 8);
    let lower = upper.to_ascii_lowercase();
    assert_ne!(upper, lower);
    let signed_upper = sign_call(&seed, 7, &upper, vec![1, 2], 3, 21_000, 500, LOCAL_CHAIN_ID);
    let signed_lower = sign_call(&seed, 7, &lower, vec![1, 2], 3, 21_000, 500, LOCAL_CHAIN_ID);
    assert_eq!(signed_upper.tx_bytes, signed_lower.tx_bytes);
    assert_eq!(signed_upper.tx_id, signed_lower.tx_id);
}

#[test]
fn the_display_string_maps_to_the_signed_chain_id() {
    assert_eq!(chain_id_from_name(qcore::LOCAL_CHAIN_NAME), LOCAL_CHAIN_ID);
    assert_eq!(chain_id_from_name(qcore::TESTNET_CHAIN_NAME), TESTNET_CHAIN_ID);
    assert_eq!(chain_id_from_name(qcore::MAINNET_CHAIN_NAME), qcore::MAINNET_CHAIN_ID);
    assert_eq!(chain_id_from_name("Q-test-net-1"), 4_032_652_574_364_075_694);
}
