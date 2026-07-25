// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::thread::sleep;
use std::time::Duration;

use qcore::contract::{event_word, OrderLayout};
use qcore::{
    account_address, contract_address, vm_deploy_address, Client, Submit, TxStatus,
};

const DEPLOYER_SEED: [u8; 32] = [11u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

// from quanta-cli emit
const BUMP_SELECTOR: [u8; 4] = [0x6c, 0xad, 0x12, 0xfc];
const BUMPED_SELECTOR: [u8; 4] = [0x6e, 0x82, 0x53, 0x1d];
// slot after the owner address
const COUNT_SLOT: u64 = 4;
const METER: u64 = 5_000_000;

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
    let url = args.next().ok_or("usage: signed_order_e2e <gateway_url> <container_hex_file> [step]")?;
    let container_file = args
        .next()
        .ok_or("usage: signed_order_e2e <gateway_url> <container_hex_file> [step]")?;
    let step: u64 = args.next().map(|s| s.parse().unwrap_or(5)).unwrap_or(5);

    let client = Client::new(url);
    let layout = OrderLayout::new(72, 80, vec![88]);

    let info = client.node_info()?;
    let fee = info.transfer_fee;
    println!(
        "network {} at height {}, fee {} {}",
        info.chain_id, info.head_height, fee, info.denomination
    );

    let deployer = account_address(&DEPLOYER_SEED, 0);
    let account = client.account(&deployer)?;
    println!("deployer {deployer}");
    println!("  nonce {} balance {} has_key {}", account.nonce, account.balance, account.has_key);
    if !account.has_key {
        return Err("the deployer is not a funded keyed genesis account, it cannot sign".into());
    }

    // 1. deploy
    let container_hex = std::fs::read_to_string(&container_file)
        .map_err(|e| format!("reading the container hex {container_file}: {e}"))?;
    let container = from_hex(container_hex.trim())?;
    let deploy_nonce = account.nonce;
    let (deploy_tx, deploy_out) =
        client.call(&DEPLOYER_SEED, 0, &vm_deploy_address(), container, METER, fee)?;
    accepted(&deploy_out, "deploy")?;
    let deploy_height = poll_finality(&client, &deploy_tx.tx_id)?;
    let contract = contract_address(&deployer, deploy_nonce)
        .ok_or("the deployer is not a q1 address")?;
    println!("\n[deploy] tx {} finalised at height {deploy_height}", deploy_tx.tx_id);
    println!("[deploy] contract {contract}");
    if client.storage(&contract)?.is_empty() {
        return Err("the contract deployed no storage, the genesis constructor did not run".into());
    }

    let count_before = client.contract_scalar(&contract, COUNT_SLOT)?;
    println!("[deploy] count before {count_before}");
    if count_before != 0 {
        return Err(format!("the freshly deployed count is {count_before}, expected 0"));
    }

    // 2. owner's bump
    let (bump_tx, bump_out, order) = client.call_signed_order(
        &DEPLOYER_SEED,
        0,
        &contract,
        BUMP_SELECTOR,
        &layout,
        &[step],
        &DEPLOYER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&bump_out, "bump")?;
    println!("\n[bump] order signer {}", hex(&order.signer));
    println!("[bump] order nonce {}", order.nonce);
    println!(
        "[bump] verify region: public key {} bytes, signature {} bytes, message {} bytes at offset {}",
        order.public_key.len(),
        order.signature.len(),
        order.message.len(),
        qcore::contract::DEFAULT_REGION_OFFSET
    );
    println!("[bump] call args {} bytes (4 selector + {} memory)", order.call_args.len(), order.user_memory.len());
    let bump_height = poll_finality(&client, &bump_tx.tx_id)?;
    println!("[bump] tx {} finalised at height {bump_height}", bump_tx.tx_id);

    let count_after = client.contract_scalar(&contract, COUNT_SLOT)?;
    println!("[bump] count after {count_after}");
    if count_after != count_before + step {
        return Err(format!(
            "the count is {count_after} after a bump by {step}, expected {}",
            count_before + step
        ));
    }
    let bumped = find_event(&client, &contract, BUMPED_SELECTOR, bump_height)?
        .ok_or("the bump recorded no Bumped event")?;
    let (event_height, data) = bumped;
    let value = event_word(&data).ok_or("the Bumped event payload is not one word")?;
    println!("[bump] Bumped event at height {event_height}, selector {}, value {value}", hex(&BUMPED_SELECTOR));
    if value != count_after {
        return Err(format!("the Bumped event carried {value}, expected {count_after}"));
    }
    println!("[bump] PROOF: count advanced {count_before} -> {count_after} and the event recorded the new count");

    // 3. wrong key
    let (wrong_tx, wrong_out, wrong_order) = client.call_signed_order(
        &DEPLOYER_SEED,
        0,
        &contract,
        BUMP_SELECTOR,
        &layout,
        &[step],
        &STRANGER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&wrong_out, "wrong-key bump")?;
    println!("\n[wrong key] order signed by stranger {}", hex(&wrong_order.signer));
    let wrong_height = poll_finality(&client, &wrong_tx.tx_id)?;
    println!("[wrong key] tx {} finalised at height {wrong_height}", wrong_tx.tx_id);
    let count_wrong = client.contract_scalar(&contract, COUNT_SLOT)?;
    println!("[wrong key] count {count_wrong}");
    if count_wrong != count_after {
        return Err(format!(
            "a stranger's order changed the count from {count_after} to {count_wrong}, the binding failed"
        ));
    }
    if find_event(&client, &contract, BUMPED_SELECTOR, wrong_height)?.is_some() {
        return Err("a stranger's order recorded a Bumped event, the binding failed".into());
    }
    println!("[wrong key] PROOF: the contract refused a non owner, count unchanged and no event");

    // 4. replay
    let replay_caller = client.account(&deployer)?;
    let replay = qcore::sign_call(
        &DEPLOYER_SEED,
        0,
        &contract,
        order.call_args.clone(),
        replay_caller.nonce,
        METER,
        fee,
        qcore::chain_id_from_name(&info.chain_id),
    );
    let replay_out = client.submit(&replay.tx_bytes)?;
    accepted(&replay_out, "replay")?;
    println!("\n[replay] resubmitted the owner's nonce {} order as tx {}", order.nonce, replay.tx_id);
    let replay_height = poll_finality(&client, &replay.tx_id)?;
    println!("[replay] tx finalised at height {replay_height}");
    let count_replay = client.contract_scalar(&contract, COUNT_SLOT)?;
    println!("[replay] count {count_replay}");
    if count_replay != count_after {
        return Err(format!(
            "a replayed order changed the count from {count_after} to {count_replay}, the nonce failed"
        ));
    }
    if find_event(&client, &contract, BUMPED_SELECTOR, replay_height)?.is_some() {
        return Err("a replayed order recorded a Bumped event, the nonce failed".into());
    }
    println!("[replay] PROOF: the contract refused the replayed order, count unchanged and no event");

    Ok(())
}

fn accepted(outcome: &Submit, what: &str) -> Result<(), String> {
    match outcome {
        Submit::Accepted { .. } => Ok(()),
        Submit::Rejected { reason, .. } => Err(format!("the {what} submission was rejected: {reason}")),
    }
}

fn poll_finality(client: &Client, tx_id: &str) -> Result<u64, String> {
    for _ in 0..120 {
        match client.transaction(tx_id)? {
            TxStatus::Finalised { height, .. } => return Ok(height),
            TxStatus::Pending => sleep(Duration::from_millis(250)),
            TxStatus::Unknown => sleep(Duration::from_millis(250)),
        }
    }
    Err(format!("transaction {tx_id} did not finalise within the window"))
}

// exact height isolates each block
fn find_event(
    client: &Client,
    contract: &str,
    selector: [u8; 4],
    height: u64,
) -> Result<Option<(u64, Vec<u8>)>, String> {
    for event in client.events(height)? {
        if event.contract == contract && event.selector == selector {
            return Ok(Some((height, event.data)));
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "the container hex is not hex".to_string()))
        .collect()
}
