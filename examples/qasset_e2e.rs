use std::thread::sleep;
use std::time::Duration;

use qcore::contract::{DeployParam, FieldArg, FieldValue};
use qcore::{account_address, Client, Submit, TxStatus};

const DEPLOYER_SEED: [u8; 32] = [11u8; 32];
const HOLDER2_SEED: [u8; 32] = [33u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

// ground truth: quanta-cli emit
const MINT_SELECTOR: [u8; 4] = [0x3e, 0xcc, 0xb9, 0xbc];
const TRANSFER_SELECTOR: [u8; 4] = [0xb8, 0x4d, 0xbd, 0x2c];
const MINTED_SELECTOR: [u8; 4] = [0xaf, 0x05, 0xf8, 0x0a];
const TRANSFERRED_SELECTOR: [u8; 4] = [0xd2, 0x63, 0xee, 0x7a];

const MINT_TO_OFF: u64 = 72;
const MINT_SCHEME_OFF: u64 = 104;
const MINT_PTR_OFF: u64 = 112;
const MINT_AMOUNT_OFF: u64 = 120;
const XFER_TO_OFF: u64 = 72;
const XFER_AMOUNT_OFF: u64 = 104;

const SUPPLY_SLOT: u64 = 4;
const BAL_BASE: u64 = 1 << 40;
const METER: u64 = 6_000_000;
const REGION_OFF: u64 = qcore::contract::DEFAULT_REGION_OFFSET;

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
    let url = args.next().ok_or("usage: qasset_e2e <gateway_url> <container_hex_file> [mint] [transfer]")?;
    let container_file = args.next().ok_or("usage: qasset_e2e <gateway_url> <container_hex_file> [mint] [transfer]")?;
    let mint_amount: u64 = args.next().map(|s| s.parse().unwrap_or(1_000_000)).unwrap_or(1_000_000);
    let transfer_amount: u64 = args.next().map(|s| s.parse().unwrap_or(250_000)).unwrap_or(250_000);

    let client = Client::new(url);
    let info = client.node_info()?;
    let fee = info.transfer_fee;
    println!("network {} at height {}, fee {} {}", info.chain_id, info.head_height, fee, info.denomination);

    let owner = account_address(&DEPLOYER_SEED, 0);
    let holder2 = account_address(&HOLDER2_SEED, 0);
    let owner_id = address_payload(&owner)?;
    let holder2_id = address_payload(&holder2)?;

    let account = client.account(&owner)?;
    println!("owner/deployer {owner}");
    println!("  nonce {} balance {} has_key {}", account.nonce, account.balance, account.has_key);
    if !account.has_key {
        return Err("the deployer is not a funded keyed genesis account, it cannot sign".into());
    }

    let container = from_hex(std::fs::read_to_string(&container_file).map_err(|e| format!("reading {container_file}: {e}"))?.trim())?;
    let (deploy_tx, deploy_out, contract) = client.deploy_with_params(
        &DEPLOYER_SEED,
        0,
        &container,
        &[DeployParam::Address(owner_id), DeployParam::U128(0)],
        METER,
        fee,
    )?;
    accepted(&deploy_out, "deploy")?;
    let deploy_height = poll_finality(&client, &deploy_tx.tx_id)?;
    println!("\n[deploy] tx {} finalised at height {deploy_height}", deploy_tx.tx_id);
    println!("[deploy] contract {contract}");
    let storage = client.storage(&contract)?;
    if storage.is_empty() {
        return Err("the contract deployed no storage, the genesis constructor did not run".into());
    }
    for (i, want) in owner_id.chunks(8).enumerate() {
        let got = client.contract_scalar(&contract, i as u64)?;
        if got != u64::from_be_bytes(want.try_into().unwrap()) {
            return Err(format!("owner slot {i} is {got}, not the deployer address word"));
        }
    }
    let supply0 = client.contract_scalar(&contract, SUPPLY_SLOT)?;
    println!("[deploy] owner is the deployer, initial supply {supply0}");
    if supply0 != 0 {
        return Err(format!("the initial supply is {supply0}, expected the deploy parameter 0"));
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after deploy")?;

    let (mint_tx, mint_out, mint_order) = client.call_typed_order(
        &DEPLOYER_SEED,
        0,
        &contract,
        MINT_SELECTOR,
        MINT_SCHEME_OFF,
        MINT_PTR_OFF,
        REGION_OFF,
        &[
            FieldArg { offset: MINT_AMOUNT_OFF, value: FieldValue::Word(mint_amount) },
            FieldArg { offset: MINT_TO_OFF, value: FieldValue::Address(owner_id) },
        ],
        &DEPLOYER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&mint_out, "mint")?;
    let mint_height = poll_finality(&client, &mint_tx.tx_id)?;
    println!("\n[mint] tx {} finalised at height {mint_height}", mint_tx.tx_id);
    println!("[mint] owner signed order, signer {}, nonce {}", hex(&mint_order.signer), mint_order.nonce);
    let supply1 = client.contract_scalar(&contract, SUPPLY_SLOT)?;
    let bal_owner1 = client.contract_map(&contract, BAL_BASE, &owner_id)?;
    println!("[mint] supply {supply0} -> {supply1}, holder1(owner) balance {bal_owner1}");
    if supply1 != supply0 + mint_amount || bal_owner1 != mint_amount {
        return Err(format!("mint did not credit: supply {supply1}, balance {bal_owner1}, expected {mint_amount}"));
    }
    let minted = find_event(&client, &contract, MINTED_SELECTOR, mint_height)?.ok_or("the mint recorded no Minted event")?;
    let minted_amount = event_amount(&minted, 1)?;
    println!("[mint] Minted event amount {minted_amount}");
    if minted_amount != mint_amount {
        return Err(format!("the Minted event carried {minted_amount}, expected {mint_amount}"));
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after mint")?;
    println!("[mint] PROOF: supply and holder1 balance rose to {mint_amount}, event recorded");

    let xfer_args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: XFER_TO_OFF, value: FieldValue::Address(holder2_id) },
            FieldArg { offset: XFER_AMOUNT_OFF, value: FieldValue::Word(transfer_amount) },
        ],
    )?;
    let (xfer_tx, xfer_out) = client.call(&DEPLOYER_SEED, 0, &contract, xfer_args, METER, fee)?;
    accepted(&xfer_out, "transfer")?;
    let xfer_height = poll_finality(&client, &xfer_tx.tx_id)?;
    println!("\n[transfer] tx {} finalised at height {xfer_height}", xfer_tx.tx_id);
    let bal_owner2 = client.contract_map(&contract, BAL_BASE, &owner_id)?;
    let bal_holder2 = client.contract_map(&contract, BAL_BASE, &holder2_id)?;
    let supply2 = client.contract_scalar(&contract, SUPPLY_SLOT)?;
    println!("[transfer] holder1 {bal_owner1} -> {bal_owner2}, holder2 0 -> {bal_holder2}, supply {supply2}");
    if bal_owner2 != mint_amount - transfer_amount || bal_holder2 != transfer_amount {
        return Err(format!("transfer did not move balance: holder1 {bal_owner2}, holder2 {bal_holder2}"));
    }
    let transferred = find_event(&client, &contract, TRANSFERRED_SELECTOR, xfer_height)?.ok_or("the transfer recorded no Transferred event")?;
    let xfer_evt_amount = event_amount(&transferred, 2)?;
    println!("[transfer] Transferred event amount {xfer_evt_amount}");
    if xfer_evt_amount != transfer_amount {
        return Err(format!("the Transferred event carried {xfer_evt_amount}, expected {transfer_amount}"));
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after transfer")?;
    println!("[transfer] PROOF: balance moved holder1 -> holder2, sum of balances still equals supply");

    let (wrong_tx, wrong_out, wrong_order) = client.call_typed_order(
        &DEPLOYER_SEED,
        0,
        &contract,
        MINT_SELECTOR,
        MINT_SCHEME_OFF,
        MINT_PTR_OFF,
        REGION_OFF,
        &[
            FieldArg { offset: MINT_AMOUNT_OFF, value: FieldValue::Word(mint_amount) },
            FieldArg { offset: MINT_TO_OFF, value: FieldValue::Address(holder2_id) },
        ],
        &STRANGER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&wrong_out, "non-owner mint")?;
    let wrong_height = poll_finality(&client, &wrong_tx.tx_id)?;
    println!("\n[non-owner mint] tx {} finalised at height {wrong_height}, signer {}", wrong_tx.tx_id, hex(&wrong_order.signer));
    let supply_w = client.contract_scalar(&contract, SUPPLY_SLOT)?;
    if supply_w != supply2 {
        return Err(format!("a non owner mint changed supply from {supply2} to {supply_w}, the binding failed"));
    }
    if find_event(&client, &contract, MINTED_SELECTOR, wrong_height)?.is_some() {
        return Err("a non owner mint recorded a Minted event, the binding failed".into());
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after non-owner mint")?;
    println!("[non-owner mint] PROOF: refused, supply unchanged at {supply_w} and no event");

    let replay_caller = client.account(&owner)?;
    let replay = qcore::sign_call(&DEPLOYER_SEED, 0, &contract, mint_order.call_args.clone(), replay_caller.nonce, METER, fee, qcore::chain_id_from_name(&info.chain_id));
    accepted(&client.submit(&replay.tx_bytes)?, "replay")?;
    let replay_height = poll_finality(&client, &replay.tx_id)?;
    println!("\n[replay] resubmitted the owner's nonce {} order as tx {}, finalised at height {replay_height}", mint_order.nonce, replay.tx_id);
    let supply_r = client.contract_scalar(&contract, SUPPLY_SLOT)?;
    if supply_r != supply2 {
        return Err(format!("a replayed mint changed supply from {supply2} to {supply_r}, the nonce failed"));
    }
    if find_event(&client, &contract, MINTED_SELECTOR, replay_height)?.is_some() {
        return Err("a replayed mint recorded a Minted event, the nonce failed".into());
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after replay")?;
    println!("[replay] PROOF: refused, supply unchanged at {supply_r} and no event");

    let bal_before = client.contract_map(&contract, BAL_BASE, &owner_id)?;
    let overdraw = bal_before + 1;
    let over_args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: XFER_TO_OFF, value: FieldValue::Address(holder2_id) },
            FieldArg { offset: XFER_AMOUNT_OFF, value: FieldValue::Word(overdraw) },
        ],
    )?;
    let (over_tx, over_out) = client.call(&DEPLOYER_SEED, 0, &contract, over_args, METER, fee)?;
    accepted(&over_out, "overdrawn transfer")?;
    let over_height = poll_finality(&client, &over_tx.tx_id)?;
    println!("\n[overdraw] tried to move {overdraw} of a {bal_before} balance, tx {} finalised at height {over_height}", over_tx.tx_id);
    let bal_owner_after = client.contract_map(&contract, BAL_BASE, &owner_id)?;
    let bal_holder2_after = client.contract_map(&contract, BAL_BASE, &holder2_id)?;
    if bal_owner_after != bal_before || bal_holder2_after != transfer_amount {
        return Err(format!("an overdrawn transfer moved balance: holder1 {bal_owner_after}, holder2 {bal_holder2_after}"));
    }
    if find_event(&client, &contract, TRANSFERRED_SELECTOR, over_height)?.is_some() {
        return Err("an overdrawn transfer recorded a Transferred event, the checked debit failed".into());
    }
    conservation(&client, &contract, &[&owner_id, &holder2_id], "after overdrawn transfer")?;
    println!("[overdraw] PROOF: reverted, holder1 still {bal_owner_after} and holder2 still {bal_holder2_after}");

    Ok(())
}

fn conservation(client: &Client, contract: &str, holders: &[&[u8; 32]], at: &str) -> Result<(), String> {
    let supply = client.contract_scalar(contract, SUPPLY_SLOT)?;
    let mut sum = 0u64;
    let mut parts = Vec::new();
    for (i, h) in holders.iter().enumerate() {
        let b = client.contract_map(contract, BAL_BASE, h)?;
        sum += b;
        parts.push(format!("holder{}={b}", i + 1));
    }
    println!("    [conservation {at}] supply={supply} {} sum={sum}", parts.join(" "));
    if sum != supply {
        return Err(format!("conservation broke {at}: sum of balances {sum} != supply {supply}"));
    }
    Ok(())
}

fn event_amount(data: &[u8], word_index: usize) -> Result<u64, String> {
    let start = word_index * 8;
    data.get(start..start + 8)
        .ok_or("the event payload is shorter than its amount word".to_string())
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

fn address_payload(address: &str) -> Result<[u8; 32], String> {
    let payload = qtv_idfmt::parse_address(address).map_err(|_| "not a Q1 address")?;
    payload.as_slice().try_into().map_err(|_| "the address payload is not thirty two bytes".to_string())
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
            TxStatus::Pending | TxStatus::Unknown => sleep(Duration::from_millis(250)),
        }
    }
    Err(format!("transaction {tx_id} did not finalise within the window"))
}

fn find_event(client: &Client, contract: &str, selector: [u8; 4], height: u64) -> Result<Option<Vec<u8>>, String> {
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "the container hex is not hex".to_string()))
        .collect()
}
