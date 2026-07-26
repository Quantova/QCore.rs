// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The frozen transaction signing vectors are the cross language source of truth. This test drives

use qcore::json::{self, Json};
use qcore::{account_address, sign_payable_call, LOCAL_CHAIN_ID, SEED_LEN};

const VECTORS: &str = include_str!("vectors.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(v: &Json, key: &str) -> String {
    v.get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("the vector field {key} is a string"))
        .to_string()
}

fn number(v: &Json, key: &str) -> u64 {
    v.get(key)
        .and_then(Json::as_u64)
        .unwrap_or_else(|| panic!("the vector field {key} is a number"))
}

fn seed(v: &Json) -> [u8; SEED_LEN] {
    json::from_hex(&text(v, "seed"))
        .expect("a seed is hex")
        .as_slice()
        .try_into()
        .expect("a seed is thirty two bytes")
}

#[test]
fn the_frozen_vectors_reproduce_from_the_signing_core() {
    let doc = json::parse(VECTORS).expect("the vectors file parses");
    assert_eq!(text(&doc, "domain"), "quantova.transaction.v1");
    let vectors = doc
        .get("vectors")
        .and_then(Json::as_array)
        .expect("a vectors array");
    assert!(!vectors.is_empty(), "the vector set carries at least one case");

    for v in vectors {
        let name = text(v, "name");
        let seed = seed(v);
        let index = number(v, "index");
        let target = text(v, "target");
        let args = json::from_hex(&text(v, "args")).expect("the args are hex");
        let nonce = number(v, "nonce");
        let meter_limit = number(v, "meter_limit");
        let fee = text(v, "fee").parse::<u128>().expect("a fee is a whole number");
        let value = number(v, "value");
        let chain_id = text(v, "chain_id")
            .parse::<u64>()
            .expect("a chain id is a whole number");

        assert_eq!(chain_id, LOCAL_CHAIN_ID, "{name} pins the running chain id");

        let derived = account_address(&seed, index);
        assert_eq!(derived, text(v, "from"), "{name} derives the sender");
        assert!(
            target.starts_with("Q1") && target == target.to_ascii_uppercase(),
            "{name} target renders uppercase Q1"
        );
        assert!(
            derived.starts_with("Q1") && derived == derived.to_ascii_uppercase(),
            "{name} sender renders uppercase Q1"
        );

        let signed = sign_payable_call(
            &seed,
            index,
            &target,
            args.clone(),
            value,
            nonce,
            meter_limit,
            fee,
            chain_id,
        )
        .unwrap();
        assert_eq!(signed.from, text(v, "from"), "{name} from");
        assert_eq!(signed.tx_id, text(v, "tx_id"), "{name} transaction id");
        assert_eq!(hex(&signed.tx_bytes), text(v, "tx_bytes"), "{name} signed bytes");

        let lowered = target.to_ascii_lowercase();
        let recased = sign_payable_call(
            &seed, index, &lowered, args, value, nonce, meter_limit, fee, chain_id,
        )
        .unwrap();
        assert_eq!(recased.tx_bytes, signed.tx_bytes, "{name} case holds the bytes");
        assert_eq!(recased.tx_id, signed.tx_id, "{name} case holds the id");
    }
}
