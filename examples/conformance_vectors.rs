// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let sender = qcore::account_address(&seed, 7);
    let target = qcore::account_address(&seed, 8);
    println!("sender {sender}");
    println!("target {target}");

    let transfer = qcore::sign_call(
        &seed,
        7,
        &target,
        vec![0xde, 0xad, 0xbe, 0xef],
        3,
        21_000,
        1_000_000,
        qtv_tx::LOCAL_CHAIN_ID,
        0,
    )
    .expect("sign_call");
    let body = qtv_tx::Body::with_context(
        sender.clone(),
        3,
        21_000,
        1_000_000,
        qtv_tx::Call::new(target.clone(), vec![0xde, 0xad, 0xbe, 0xef]),
        0,
        qtv_tx::LOCAL_CHAIN_ID,
    )
    .calling();
    println!("transfer.body_bytes {}", hex(&qtv_codec::to_bytes(&body)));
    println!("transfer.tx_id {}", transfer.tx_id);
    println!("transfer.tx_hex {}", hex(&transfer.tx_bytes));

    let payable = qcore::sign_payable_call(
        &seed,
        7,
        &target,
        vec![0xde, 0xad, 0xbe, 0xef],
        250_000,
        3,
        21_000,
        1_000_000,
        4_032_652_574_364_075_694,
        0,
    )
    .expect("sign_payable_call");
    println!("payable.tx_id {}", payable.tx_id);
    println!("payable.tx_hex {}", hex(&payable.tx_bytes));
}
