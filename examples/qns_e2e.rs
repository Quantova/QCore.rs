// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::thread::sleep;
use std::time::Duration;

use qcore::contract::{
    build_call_args, build_typed_order_call, name_key, order_layout_hash, order_signer,
    storage_value, DeployParam, FieldArg, FieldValue, OrderLayoutField, DEFAULT_REGION_OFFSET,
};
use qcore::{account_address, chain_id_from_name, Client, Submit, TxStatus};

const OWNER_A_SEED: [u8; 32] = [11u8; 32];
const OWNER_B_SEED: [u8; 32] = [33u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

const GUARDIAN_SEEDS: [[u8; 32]; 7] = [
    OWNER_A_SEED,
    [41u8; 32],
    [42u8; 32],
    [43u8; 32],
    [44u8; 32],
    [45u8; 32],
    [46u8; 32],
];

const REGISTER_SELECTOR: [u8; 4] = [0xa2, 0xc4, 0x8b, 0x6d];
const RENEW_SELECTOR: [u8; 4] = [0xea, 0x60, 0xbe, 0x22];
const SET_RESOLVED_SELECTOR: [u8; 4] = [0xea, 0x5f, 0x21, 0x92];
const TRANSFER_SELECTOR: [u8; 4] = [0xf7, 0xe4, 0xde, 0x7b];
const WITHDRAW_SELECTOR: [u8; 4] = [0x60, 0xf4, 0x42, 0x1a];

const REGISTERED_SELECTOR: [u8; 4] = [0xc1, 0x06, 0xc7, 0xf0];
const RENEWED_SELECTOR: [u8; 4] = [0xf8, 0x5f, 0xb9, 0xda];
const RESOLVED_SELECTOR: [u8; 4] = [0x48, 0x86, 0x83, 0x53];
const TRANSFERRED_SELECTOR: [u8; 4] = [0x93, 0x46, 0x83, 0x27];
const SWEPT_SELECTOR: [u8; 4] = [0x3f, 0xa8, 0xe9, 0xaa];

const LABEL_OFF: u64 = 152;
const PAYMENT_OFF: u64 = 200;
const YEARS_OFF: u64 = 192;
const TARGET_OFF: u64 = 192;
const TO_OFF: u64 = 192;
const SWEEP_TO_OFF: u64 = 152;
const SWEEP_AMOUNT_OFF: u64 = 184;
const SWEEP_EXPIRY_OFF: u64 = 200;
const SWEEP_APPROVALS_OFF: u64 = 208;
const SWEEP_THRESHOLD: usize = 5;

const BASE3_SLOT: u64 = 28;
const BASE4_SLOT: u64 = 29;
const BASE5_SLOT: u64 = 30;
const GRACE_SLOT: u64 = 31;
const AUCTION_SLOT: u64 = 32;
const START_PREMIUM_SLOT: u64 = 33;
const INTERVAL_SLOT: u64 = 34;
const VAULT_SLOT: u64 = 35;
const EXPIRY_BASE: u64 = 1 << 40;
const OWNER_OF_BASE: u64 = (1 << 40) + (1 << 32);
const RESOLVED_BASE: u64 = (1 << 40) + (2 << 32);

const YEAR: u64 = 31_536_000;
const DAY: u64 = 86_400;

const BASE_3: u64 = 500;
const BASE_4: u64 = 300;
const BASE_5_PLUS: u64 = 100;
const GRACE_PERIOD: u64 = 90 * DAY;
const AUCTION_DURATION: u64 = 60 * DAY;
const START_PREMIUM: u64 = 1 << 20;
const INTERVAL: u64 = DAY;

const METER: u64 = 14_000_000;

fn main() {
    match run() {
        Ok(()) => println!("\nALL PROOFS PASSED"),
        Err(message) => {
            eprintln!("\nFAILED: {message}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;
    let container_file = args
        .next()
        .ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;

    let client = Client::new(url);
    let info = client.node_info()?;
    let fee = qcore::vm_call_fee(info.transfer_fee, METER);
    let chain_id = chain_id_from_name(&info.chain_id);
    let genesis = qcore::parse_genesis(&info)?;
    println!(
        "network {} at height {}, fee {} {}",
        info.chain_id, info.head_height, fee, info.denomination
    );

    let a = account_address(&OWNER_A_SEED, 0);
    let b = account_address(&OWNER_B_SEED, 0);
    let stranger = account_address(&STRANGER_SEED, 0);
    let a_id = address_payload(&a)?;
    let b_id = address_payload(&b)?;
    let stranger_id = address_payload(&stranger)?;
    let guardians = guardian_set();

    println!("guardian 0 / owner A  {a}");
    println!("owner B               {b}");
    println!("non owner             {stranger}");
    for (label, addr) in [("A", &a), ("B", &b), ("stranger", &stranger)] {
        let account = client.account(addr)?;
        println!(
            "  {label} nonce {} balance {} has_key {}",
            account.nonce, account.balance, account.has_key
        );
        if !account.has_key {
            return Err(format!(
                "{label} is not a funded keyed genesis account, it cannot sign"
            ));
        }
    }

    let container = from_hex(
        std::fs::read_to_string(&container_file)
            .map_err(|e| format!("reading {container_file}: {e}"))?
            .trim(),
    )?;
    let (deploy_tx, deploy_out, contract) = client.deploy_with_params(
        &OWNER_A_SEED,
        0,
        &container,
        &deploy_params(&guardians),
        METER,
        fee,
    )?;
    accepted(&deploy_out, "deploy")?;
    let deploy_height = poll_finality(&client, &deploy_tx.tx_id)?;
    println!(
        "\n[deploy] tx {} finalised at height {deploy_height}",
        deploy_tx.tx_id
    );
    println!("[deploy] contract {contract}");
    if client.storage(&contract)?.is_empty() {
        return Err("the contract deployed no storage, the genesis constructor did not run".into());
    }
    for (g, guardian) in guardians.iter().enumerate() {
        for (w, want) in guardian.chunks(8).enumerate() {
            let slot = (g * 4 + w) as u64;
            let got = client.contract_scalar(&contract, slot)?;
            if got != u64::from_be_bytes(want.try_into().unwrap()) {
                return Err(format!("guardian {g} word {w} landed as {got}"));
            }
        }
    }
    let seeded = [
        (BASE3_SLOT, BASE_3, "base_3"),
        (BASE4_SLOT, BASE_4, "base_4"),
        (BASE5_SLOT, BASE_5_PLUS, "base_5_plus"),
        (GRACE_SLOT, GRACE_PERIOD, "grace_period"),
        (AUCTION_SLOT, AUCTION_DURATION, "auction_duration"),
        (START_PREMIUM_SLOT, START_PREMIUM, "start_premium"),
        (INTERVAL_SLOT, INTERVAL, "interval"),
    ];
    for (slot, want, name) in seeded {
        let got = client.contract_scalar(&contract, slot)?;
        if got != want {
            return Err(format!(
                "deploy parameter {name} landed as {got}, expected {want}"
            ));
        }
    }
    if client.contract_scalar(&contract, VAULT_SLOT)? != 0 {
        return Err("the vault did not start empty".into());
    }
    println!(
        "[deploy] seven guardians seeded; tiers 3/4/5+ = {BASE_3}/{BASE_4}/{BASE_5_PLUS}; grace {} days, auction {} days, start_premium {START_PREMIUM}, interval {} day",
        GRACE_PERIOD / DAY, AUCTION_DURATION / DAY, INTERVAL / DAY
    );

    let mut fees_taken = 0u64;
    let mut swept = 0u64;
    conservation(&client, &contract, fees_taken, swept, "after deploy")?;

    println!("\n--- tier pricing: one year each, distinct label lengths ---");
    register(&client, &OWNER_A_SEED, &contract, "sol", 1, fee, &a_id)?;
    fees_taken += BASE_3;
    let e_sol = expiry_of(&client, &contract, "sol")?;
    if e_sol < YEAR {
        return Err(format!("sol expiry {e_sol} is not at least a year out"));
    }
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after sol (3 char, base_3)",
    )?;
    tier_charged(&client, &contract, BASE_3, "sol", 3)?;

    register(&client, &OWNER_A_SEED, &contract, "jeff", 1, fee, &a_id)?;
    fees_taken += BASE_4;
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after jeff (4 char, base_4)",
    )?;
    tier_charged(&client, &contract, BASE_4, "jeff", 4)?;

    register(&client, &OWNER_B_SEED, &contract, "alice", 1, fee, &b_id)?;
    fees_taken += BASE_5_PLUS;
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after alice (5 char, base_5_plus)",
    )?;
    tier_charged(&client, &contract, BASE_5_PLUS, "alice", 5)?;
    println!("[tiers] PROOF: base_3 {BASE_3}, base_4 {BASE_4}, base_5_plus {BASE_5_PLUS} each hit the vault by label length");

    println!("\n--- renew within grace ---");
    let jeff_before = expiry_of(&client, &contract, "jeff")?;
    let years = 2u64;
    let renew_price = price("jeff", years);
    let renew_args = paid_name_call(RENEW_SELECTOR, "jeff", years, renew_price)?;
    let (renew_tx, renew_out) = client.call_payable(
        &OWNER_A_SEED,
        0,
        &contract,
        renew_args,
        renew_price,
        METER,
        fee,
    )?;
    accepted(&renew_out, "renew")?;
    let renew_height = poll_finality(&client, &renew_tx.tx_id)?;
    let jeff_after = expiry_of(&client, &contract, "jeff")?;
    println!("[renew jeff] {years} years, expiry {jeff_before} -> {jeff_after}");
    if jeff_after < jeff_before || jeff_after < years * YEAR {
        return Err(format!(
            "renew did not move the expiry {years} years out, {jeff_before} -> {jeff_after}"
        ));
    }
    fees_taken += renew_price;
    let renewed_evt = find_event(&client, &contract, RENEWED_SELECTOR, renew_height)?
        .ok_or("no Renewed event")?;
    if !label_window_is(&renewed_evt, "jeff")
        || word_at(&renewed_evt, 4)? != jeff_after
        || word_at(&renewed_evt, 5)? != years
    {
        return Err(
            "the Renewed event did not carry the label, the new expiry, and the term".into(),
        );
    }
    conservation(&client, &contract, fees_taken, swept, "after jeff renew")?;
    println!("[renew jeff] PROOF: the expiry moved out by the term, base_4 charged per year");

    println!("\n--- full 32 byte resolution ---");
    let target = b_id;
    let resolve_args = name_call(SET_RESOLVED_SELECTOR, "jeff", TARGET_OFF, &target)?;
    let (resolve_tx, resolve_out) =
        client.call(&OWNER_A_SEED, 0, &contract, resolve_args, METER, fee)?;
    accepted(&resolve_out, "set_resolved")?;
    let resolve_height = poll_finality(&client, &resolve_tx.tx_id)?;
    let reassembled = read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))?;
    if reassembled != target {
        return Err(format!(
            "the reassembled resolution {} does not equal the full target {}",
            hex(&reassembled),
            hex(&target)
        ));
    }
    let resolved_evt = find_event(&client, &contract, RESOLVED_SELECTOR, resolve_height)?
        .ok_or("no Resolved event")?;
    if addr_at(&resolved_evt, 64)? != target {
        return Err("the Resolved event did not carry the whole target".into());
    }
    println!("[set_resolved jeff] PROOF: all thirty two bytes of the target resolve back in full");
    conservation(&client, &contract, fees_taken, swept, "after set_resolved")?;

    println!("\n--- per name ownership negatives ---");
    let b_resolve = name_call(SET_RESOLVED_SELECTOR, "jeff", TARGET_OFF, &stranger_id)?;
    let (br_tx, br_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve, METER, fee)?;
    accepted(&br_out, "B set_resolved of a name it does not own")?;
    let br_height = poll_finality(&client, &br_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != target
        || find_event(&client, &contract, RESOLVED_SELECTOR, br_height)?.is_some()
    {
        return Err("a registered owner set_resolved a name it does not own".into());
    }
    println!("[neg1a] B could not set_resolved jeff (owned by A): reverted, resolution unchanged, no event");

    let b_transfer = name_call(TRANSFER_SELECTOR, "jeff", TO_OFF, &b_id)?;
    let (bt_tx, bt_out) = client.call(&OWNER_B_SEED, 0, &contract, b_transfer, METER, fee)?;
    accepted(&bt_out, "B transfer of a name it does not own")?;
    let bt_height = poll_finality(&client, &bt_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &name_key("jeff"))? != a_id
        || find_event(&client, &contract, TRANSFERRED_SELECTOR, bt_height)?.is_some()
    {
        return Err("a registered owner transferred a name it does not own".into());
    }
    println!("[neg1b] B could not transfer jeff (owned by A): reverted, owner still A, no event");
    println!("[neg1 ] PROOF: per name ownership binds the full owner, a different registered owner is refused");
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after B's refused attempts",
    )?;

    println!("\n--- transfer moves the binding in full ---");
    assert_owner(
        &client,
        &contract,
        "jeff",
        &a_id,
        "jeff owned by A before transfer",
    )?;
    let transfer_args = name_call(TRANSFER_SELECTOR, "jeff", TO_OFF, &b_id)?;
    let (transfer_tx, transfer_out) =
        client.call(&OWNER_A_SEED, 0, &contract, transfer_args, METER, fee)?;
    accepted(&transfer_out, "transfer")?;
    let transfer_height = poll_finality(&client, &transfer_tx.tx_id)?;
    assert_owner(
        &client,
        &contract,
        "jeff",
        &b_id,
        "jeff owned by B in full after transfer",
    )?;
    let transferred_evt = find_event(&client, &contract, TRANSFERRED_SELECTOR, transfer_height)?
        .ok_or("no Transferred event")?;
    if !label_window_is(&transferred_evt, "jeff")
        || addr_at(&transferred_evt, 32)? != a_id
        || addr_at(&transferred_evt, 64)? != b_id
    {
        return Err(
            "the Transferred event did not carry the label and the whole prior and new owner"
                .into(),
        );
    }
    println!("[transfer jeff] A -> B, owner_of[jeff] now reads B in full");

    let a_resolve_jeff = name_call(SET_RESOLVED_SELECTOR, "jeff", TARGET_OFF, &a_id)?;
    let (arj_tx, arj_out) = client.call(&OWNER_A_SEED, 0, &contract, a_resolve_jeff, METER, fee)?;
    accepted(&arj_out, "prior owner set_resolved")?;
    let arj_height = poll_finality(&client, &arj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != b_id
        || find_event(&client, &contract, RESOLVED_SELECTOR, arj_height)?.is_some()
    {
        return Err("the prior owner A set_resolved a transferred name".into());
    }
    println!(
        "[neg2a] prior owner A could not set_resolved jeff after transfer: reverted, no event"
    );

    let b_resolve_jeff = name_call(SET_RESOLVED_SELECTOR, "jeff", TARGET_OFF, &stranger_id)?;
    let (brj_tx, brj_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve_jeff, METER, fee)?;
    accepted(&brj_out, "new owner set_resolved")?;
    let brj_height = poll_finality(&client, &brj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != stranger_id {
        return Err("the new owner B could not set_resolved jeff".into());
    }
    find_event(&client, &contract, RESOLVED_SELECTOR, brj_height)?
        .ok_or("no Resolved event for the new owner")?;
    println!("[neg2b] new owner B set_resolved jeff to a full target and it reassembles in full");
    println!("[neg2 ] PROOF: transfer moved the binding, the prior owner is gone and the new owner holds it");
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after ownership move proofs",
    )?;

    println!("\n--- an unexpired name cannot be re-registered ---");
    let expiry_before = expiry_of(&client, &contract, "sol")?;
    let owner_before = read_addr_value(&client, &contract, OWNER_OF_BASE, &name_key("sol"))?;
    let vault_before = client.contract_scalar(&contract, VAULT_SLOT)?;
    let retake_price = price("sol", 5);
    let retake = paid_name_call(REGISTER_SELECTOR, "sol", 5, retake_price)?;
    let (retake_tx, retake_out) = client.call_payable(
        &STRANGER_SEED,
        0,
        &contract,
        retake,
        retake_price,
        METER,
        fee,
    )?;
    accepted(&retake_out, "retake")?;
    let retake_height = poll_finality(&client, &retake_tx.tx_id)?;
    if expiry_of(&client, &contract, "sol")? != expiry_before
        || read_addr_value(&client, &contract, OWNER_OF_BASE, &name_key("sol"))? != owner_before
        || client.contract_scalar(&contract, VAULT_SLOT)? != vault_before
        || find_event(&client, &contract, REGISTERED_SELECTOR, retake_height)?.is_some()
    {
        return Err("an unexpired name was re-registered, the freshness guard failed".into());
    }
    println!("[neg3 ] PROOF: an unexpired sol could not be re-registered, expiry and owner unchanged, no fee, no event");
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after refused retake",
    )?;

    println!("\n--- guardian quorum sweep ---");
    let sweep_layout = sweep_layout();
    println!("[sweep] layout hash {}", hex(&sweep_layout));
    let vault_now = client.contract_scalar(&contract, VAULT_SLOT)?;
    let mut forged: Vec<([u8; 32], u64, u64)> = Vec::new();
    for (index, seed) in GUARDIAN_SEEDS.iter().enumerate().take(SWEEP_THRESHOLD - 1) {
        let nonce = client.contract_nonce(&contract, &guardians[index])?;
        forged.push((*seed, index as u64, nonce));
    }
    let stranger_nonce = client.contract_nonce(&contract, &stranger_id)?;
    forged.push((STRANGER_SEED, (SWEEP_THRESHOLD - 1) as u64, stranger_nonce));
    let bad_args = sweep_call(
        chain_id,
        &genesis,
        &contract,
        &forged,
        &stranger_id,
        u128::from(vault_now),
        order_expiry(),
    )?;
    let (bad_w_tx, bad_w_out) = client.call(&STRANGER_SEED, 0, &contract, bad_args, METER, fee)?;
    accepted(&bad_w_out, "sweep with a non guardian approval")?;
    let bad_w_height = poll_finality(&client, &bad_w_tx.tx_id)?;
    if client.contract_scalar(&contract, VAULT_SLOT)? != vault_now
        || find_event(&client, &contract, SWEPT_SELECTOR, bad_w_height)?.is_some()
    {
        return Err("a sweep carrying a non guardian approval moved the vault".into());
    }
    println!("[neg4 ] PROOF: four guardians plus a stranger in the fifth seat were refused, vault unchanged, no event");
    conservation(&client, &contract, fees_taken, swept, "after refused sweep")?;

    let sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    let mut members: Vec<([u8; 32], u64, u64)> = Vec::new();
    for (index, seed) in GUARDIAN_SEEDS.iter().enumerate().take(SWEEP_THRESHOLD) {
        let nonce = client.contract_nonce(&contract, &guardians[index])?;
        members.push((*seed, index as u64, nonce));
    }
    let sweep_args = sweep_call(
        chain_id,
        &genesis,
        &contract,
        &members,
        &a_id,
        u128::from(sweep),
        order_expiry(),
    )?;
    let (w_tx, w_out) = client.call(&OWNER_A_SEED, 0, &contract, sweep_args, METER, fee)?;
    accepted(&w_out, "guardian sweep")?;
    let w_height = poll_finality(&client, &w_tx.tx_id)?;
    let vault_final = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[withdraw] five guardians swept {sweep} to A");
    println!("[withdraw] vault {sweep} -> {vault_final}");
    if vault_final != 0 {
        return Err(format!(
            "the guardian sweep left {vault_final} in the vault"
        ));
    }
    let swept_evt =
        find_event(&client, &contract, SWEPT_SELECTOR, w_height)?.ok_or("no Swept event")?;
    if addr_at(&swept_evt, 0)? != a_id || word_at(&swept_evt, 4)? != sweep {
        return Err("the Swept event carried the wrong recipient or amount".into());
    }
    swept += sweep;
    conservation(
        &client,
        &contract,
        fees_taken,
        swept,
        "after guardian sweep",
    )?;
    println!("[withdraw] PROOF: a five of seven guardian quorum swept the collected fees, vault and swept still sum to the fees taken");

    Ok(())
}

fn guardian_set() -> Vec<[u8; 32]> {
    GUARDIAN_SEEDS
        .iter()
        .map(|seed| order_signer(seed, 0))
        .collect()
}

fn deploy_params(guardians: &[[u8; 32]]) -> Vec<DeployParam> {
    vec![
        DeployParam::Guardians(guardians.to_vec()),
        DeployParam::U64(BASE_3),
        DeployParam::U64(BASE_4),
        DeployParam::U64(BASE_5_PLUS),
        DeployParam::U64(GRACE_PERIOD),
        DeployParam::U64(AUCTION_DURATION),
        DeployParam::U64(START_PREMIUM),
        DeployParam::U64(INTERVAL),
    ]
}

fn price(label: &str, years: u64) -> u64 {
    let base = match label.len() {
        3 => BASE_3,
        4 => BASE_4,
        _ => BASE_5_PLUS,
    };
    base * years
}

fn paid_name_call(
    selector: [u8; 4],
    label: &str,
    years: u64,
    payment: u64,
) -> Result<Vec<u8>, String> {
    build_call_args(
        selector,
        &[
            FieldArg {
                offset: LABEL_OFF,
                value: FieldValue::name(label),
            },
            FieldArg {
                offset: PAYMENT_OFF,
                value: FieldValue::Word(payment),
            },
            FieldArg {
                offset: YEARS_OFF,
                value: FieldValue::Word(years),
            },
        ],
    )
}

fn name_call(
    selector: [u8; 4],
    label: &str,
    address_off: u64,
    address: &[u8; 32],
) -> Result<Vec<u8>, String> {
    build_call_args(
        selector,
        &[
            FieldArg {
                offset: LABEL_OFF,
                value: FieldValue::name(label),
            },
            FieldArg {
                offset: address_off,
                value: FieldValue::Address(*address),
            },
        ],
    )
}

fn sweep_layout() -> [u8; 32] {
    order_layout_hash(
        WITHDRAW_SELECTOR,
        &[
            OrderLayoutField {
                name: "order.amount".to_string(),
                ty: "u128".to_string(),
                width: 16,
            },
            OrderLayoutField {
                name: "order.to".to_string(),
                ty: "Q_Address".to_string(),
                width: 32,
            },
        ],
    )
}

fn put_bytes(memory: &mut Vec<u8>, offset: u64, bytes: &[u8]) {
    let at = offset as usize;
    if memory.len() < at + bytes.len() {
        memory.resize(at + bytes.len(), 0);
    }
    memory[at..at + bytes.len()].copy_from_slice(bytes);
}

fn sweep_call(
    chain_id: u64,
    genesis: &[u8; 32],
    contract: &str,
    members: &[([u8; 32], u64, u64)],
    to: &[u8; 32],
    amount: u128,
    expiry: u64,
) -> Result<Vec<u8>, String> {
    let layout = sweep_layout();
    let fields = [
        FieldArg {
            offset: SWEEP_AMOUNT_OFF,
            value: FieldValue::wide(amount),
        },
        FieldArg {
            offset: SWEEP_TO_OFF,
            value: FieldValue::Address(*to),
        },
    ];
    let mut memory = Vec::new();
    put_bytes(&mut memory, SWEEP_TO_OFF, to);
    put_bytes(
        &mut memory,
        SWEEP_AMOUNT_OFF,
        &(amount as u64).to_be_bytes(),
    );
    put_bytes(
        &mut memory,
        SWEEP_AMOUNT_OFF + 8,
        &((amount >> 64) as u64).to_be_bytes(),
    );
    put_bytes(&mut memory, SWEEP_EXPIRY_OFF, &expiry.to_be_bytes());
    let mut cursor = DEFAULT_REGION_OFFSET;
    for (slot, (seed, index, nonce)) in members.iter().enumerate() {
        let scheme_off = SWEEP_APPROVALS_OFF + slot as u64 * 24;
        let ptr_off = scheme_off + 8;
        let index_off = scheme_off + 16;
        let order = build_typed_order_call(
            chain_id,
            genesis,
            contract,
            WITHDRAW_SELECTOR,
            &layout,
            scheme_off,
            ptr_off,
            SWEEP_EXPIRY_OFF,
            cursor,
            &fields,
            seed,
            0,
            *nonce,
            expiry,
        )?;
        let mut region = order.public_key.clone();
        region.extend_from_slice(&order.signature);
        region.extend_from_slice(&order.message);
        put_bytes(&mut memory, scheme_off, &1u64.to_be_bytes());
        put_bytes(&mut memory, ptr_off, &cursor.to_be_bytes());
        put_bytes(&mut memory, index_off, &index.to_be_bytes());
        put_bytes(&mut memory, cursor, &region);
        cursor += region.len() as u64;
    }
    let mut args = WITHDRAW_SELECTOR.to_vec();
    args.extend_from_slice(&memory);
    Ok(args)
}

fn register(
    client: &Client,
    seed: &[u8; 32],
    contract: &str,
    label: &str,
    years: u64,
    fee: u128,
    owner: &[u8; 32],
) -> Result<u64, String> {
    let vault_before = client.contract_scalar(contract, VAULT_SLOT)?;
    let payment = price(label, years);
    let args = paid_name_call(REGISTER_SELECTOR, label, years, payment)?;
    let (tx, out) = client.call_payable(seed, 0, contract, args, payment, METER, fee)?;
    accepted(&out, "register")?;
    let height = poll_finality(client, &tx.tx_id)?;
    let vault_after = client.contract_scalar(contract, VAULT_SLOT)?;
    println!("\n[register {label}] tx {} finalised at height {height}, vault {vault_before} -> {vault_after}", tx.tx_id);
    assert_owner(
        client,
        contract,
        label,
        owner,
        &format!("{label} owned in full"),
    )?;
    let evt =
        find_event(client, contract, REGISTERED_SELECTOR, height)?.ok_or("no Registered event")?;
    if !label_window_is(&evt, label) {
        return Err(format!(
            "the Registered event did not carry the label window for {label}"
        ));
    }
    if addr_at(&evt, 32)? != *owner {
        return Err("the Registered event did not carry the whole owner".into());
    }
    let expiry = expiry_of(client, contract, label)?;
    if word_at(&evt, 8)? != expiry || word_at(&evt, 9)? != years {
        return Err("the Registered event did not carry the expiry then the term".into());
    }
    Ok(height)
}

fn tier_charged(
    client: &Client,
    contract: &str,
    want: u64,
    label: &str,
    len: usize,
) -> Result<(), String> {
    println!("    [tier] {label} is {len} characters, charged {want} for one year");
    let expiry = expiry_of(client, contract, label)?;
    if expiry == 0 {
        return Err(format!("{label} did not register an expiry"));
    }
    Ok(())
}

fn expiry_of(client: &Client, contract: &str, label: &str) -> Result<u64, String> {
    client.contract_map(contract, EXPIRY_BASE, &name_key(label))
}

fn conservation(
    client: &Client,
    contract: &str,
    fees_taken: u64,
    swept: u64,
    at: &str,
) -> Result<(), String> {
    let vault = client.contract_scalar(contract, VAULT_SLOT)?;
    println!("    [conservation {at}] vault={vault} swept={swept} fees_taken={fees_taken}");
    if vault + swept != fees_taken {
        return Err(format!(
            "conservation broke {at}: vault {vault} plus swept {swept} != fees taken {fees_taken}"
        ));
    }
    Ok(())
}

fn addr_word_key(base: u64, key: &[u8; 32], word: u64) -> [u8; 32] {
    let mut input = base.to_be_bytes().to_vec();
    input.extend_from_slice(key);
    input.extend_from_slice(&word.to_be_bytes());
    qtv_crypto::sha3::sha3_256(&input)
}

fn read_addr_value(
    client: &Client,
    contract: &str,
    base: u64,
    key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let slots = client.storage(contract)?;
    let mut out = [0u8; 32];
    for i in 0..4u64 {
        let word = storage_value(&slots, &addr_word_key(base, key, i));
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    Ok(out)
}

fn assert_owner(
    client: &Client,
    contract: &str,
    label: &str,
    want: &[u8; 32],
    what: &str,
) -> Result<(), String> {
    let got = read_addr_value(client, contract, OWNER_OF_BASE, &name_key(label))?;
    if &got != want {
        return Err(format!(
            "{what}: owner_of reads {} not {}",
            hex(&got),
            hex(want)
        ));
    }
    println!("    [owner] {what}: {}", hex(&got));
    Ok(())
}

fn label_window_is(data: &[u8], label: &str) -> bool {
    let bytes = label.as_bytes();
    data.len() >= 32
        && &data[..bytes.len()] == bytes
        && data[bytes.len()..32].iter().all(|&b| b == 0)
}

fn word_at(data: &[u8], word_index: usize) -> Result<u64, String> {
    let start = word_index * 8;
    data.get(start..start + 8)
        .ok_or("the event payload is shorter than its word".to_string())
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

fn addr_at(data: &[u8], byte_off: usize) -> Result<[u8; 32], String> {
    data.get(byte_off..byte_off + 32)
        .ok_or("the event payload is shorter than a full address".to_string())
        .map(|b| b.try_into().unwrap())
}

fn address_payload(address: &str) -> Result<[u8; 32], String> {
    let payload = qtv_idfmt::parse_address(address).map_err(|_| "not a Q1 address")?;
    payload
        .as_slice()
        .try_into()
        .map_err(|_| "the address payload is not thirty two bytes".to_string())
}

fn accepted(outcome: &Submit, what: &str) -> Result<(), String> {
    match outcome {
        Submit::Accepted { .. } => Ok(()),
        Submit::Rejected { reason, .. } => {
            Err(format!("the {what} submission was rejected: {reason}"))
        }
    }
}

fn poll_finality(client: &Client, tx_id: &str) -> Result<u64, String> {
    for _ in 0..240 {
        match client.transaction(tx_id)? {
            TxStatus::Finalised { height, .. }
            | TxStatus::Included { height, .. }
            | TxStatus::Unverified { height, .. } => return Ok(height),
            TxStatus::Pending | TxStatus::Unknown => sleep(Duration::from_millis(250)),
        }
    }
    Err(format!(
        "transaction {tx_id} did not finalise within the window"
    ))
}

fn find_event(
    client: &Client,
    contract: &str,
    selector: [u8; 4],
    height: u64,
) -> Result<Option<Vec<u8>>, String> {
    for event in client.events(height)? {
        if event.contract == contract && event.selector == selector {
            return Ok(Some(event.data));
        }
    }
    Ok(None)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("the container hex has an odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| "the container hex is not hex".to_string())
        })
        .collect()
}

fn order_expiry() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_add(3600)
}
