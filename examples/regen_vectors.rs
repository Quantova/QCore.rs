// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::json::{self, Json};
use qcore::{account_address, sign_payable_call, SEED_LEN};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(v: &Json, key: &str) -> String {
    v.get(key)
        .and_then(Json::as_str)
        .expect("string")
        .to_string()
}

fn number(v: &Json, key: &str) -> u64 {
    v.get(key).and_then(Json::as_u64).expect("number")
}

fn main() {
    let raw = std::fs::read_to_string("tests/vectors.json").expect("vectors");
    let doc = json::parse(&raw).expect("parse");
    for v in doc.get("vectors").and_then(Json::as_array).expect("array") {
        let seed: [u8; SEED_LEN] = json::from_hex(&text(v, "seed"))
            .expect("hex")
            .as_slice()
            .try_into()
            .expect("seed");
        let index = number(v, "index");
        let signed = sign_payable_call(
            &seed,
            index,
            &text(v, "target"),
            json::from_hex(&text(v, "args")).expect("hex"),
            number(v, "value"),
            number(v, "nonce"),
            number(v, "meter_limit"),
            text(v, "fee").parse().expect("fee"),
            text(v, "chain_id").parse().expect("chain id"),
            0,
        )
        .expect("sign");
        println!(
            "{}\tfrom\t{}",
            text(v, "name"),
            account_address(&seed, index)
        );
        println!("{}\ttx_id\t{}", text(v, "name"), signed.tx_id);
        println!("{}\ttx_bytes\t{}", text(v, "name"), hex(&signed.tx_bytes));
    }
}
