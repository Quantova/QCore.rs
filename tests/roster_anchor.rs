// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::finality::{parse_roster, roster_commitment_of};
use qcore::json::to_hex;

fn roster_json(members: &[(u64, &str, &str, &str)]) -> String {
    let parts: Vec<String> = members
        .iter()
        .map(|(id, pk, stake, root)| {
            format!(
                "{{\"id\":{id},\"attest_pk\":\"{pk}\",\"stake\":\"{stake}\",\"root\":\"{root}\",\"root_slots\":\"65536\"}}"
            )
        })
        .collect();
    format!("[{}]", parts.join(","))
}

#[test]
fn a_gateway_roster_that_is_not_the_pinned_one_cannot_reproduce_its_commitment() {
    let (p1, _) = qtv_crypto::ml_dsa::keygen(&[1u8; 32]);
    let (p2, _) = qtv_crypto::ml_dsa::keygen(&[2u8; 32]);
    let (p3, _) = qtv_crypto::ml_dsa::keygen(&[3u8; 32]);
    let (p4, _) = qtv_crypto::ml_dsa::keygen(&[4u8; 32]);
    let (evil, _) = qtv_crypto::ml_dsa::keygen(&[200u8; 32]);
    let k1 = to_hex(&p1);
    let k2 = to_hex(&p2);
    let k3 = to_hex(&p3);
    let k4 = to_hex(&p4);
    let ke = to_hex(&evil);
    let root = "00".repeat(32);

    let genesis = parse_roster(&roster_json(&[
        (1, &k1, "2000", &root),
        (2, &k2, "2000", &root),
        (3, &k3, "2000", &root),
        (4, &k4, "2000", &root),
    ]))
    .expect("genesis roster parses");
    let pin = roster_commitment_of(0, &genesis);

    let same = parse_roster(&roster_json(&[
        (1, &k1, "2000", &root),
        (2, &k2, "2000", &root),
        (3, &k3, "2000", &root),
        (4, &k4, "2000", &root),
    ]))
    .expect("parses");
    assert_eq!(roster_commitment_of(0, &same), pin, "the pinned roster reproduces its own commitment");

    let forged_key = parse_roster(&roster_json(&[
        (1, &ke, "2000", &root),
        (2, &k2, "2000", &root),
        (3, &k3, "2000", &root),
        (4, &k4, "2000", &root),
    ]))
    .expect("parses");
    assert_ne!(roster_commitment_of(0, &forged_key), pin, "a swapped validator key cannot match the pin");

    let inflated = parse_roster(&roster_json(&[
        (1, &k1, "999999", &root),
        (2, &k2, "2000", &root),
        (3, &k3, "2000", &root),
        (4, &k4, "2000", &root),
    ]))
    .expect("parses");
    assert_ne!(roster_commitment_of(0, &inflated), pin, "an inflated stake cannot match the pin");

    let dropped = parse_roster(&roster_json(&[
        (1, &k1, "2000", &root),
        (2, &k2, "2000", &root),
        (3, &k3, "2000", &root),
    ]))
    .expect("parses");
    assert_ne!(roster_commitment_of(0, &dropped), pin, "a dropped validator cannot match the pin");
}
