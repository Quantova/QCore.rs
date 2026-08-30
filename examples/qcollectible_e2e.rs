// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::thread::sleep;
use std::time::Duration;

use qcore::contract::{id_key, DeployParam, FieldArg, FieldValue};
use qcore::{account_address, Client, Submit, TxStatus};

const OWNER_A_SEED: [u8; 32] = [11u8; 32];
const OWNER_B_SEED: [u8; 32] = [33u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

const MINT_SELECTOR: [u8; 4] = [0x3e, 0xcc, 0xb9, 0xbc];
const TRANSFER_SELECTOR: [u8; 4] = [0xf8, 0xe2, 0xf9, 0xcd];

const MINTED_SELECTOR: [u8; 4] = [0x23, 0xb2, 0xd7, 0x61];
const TRANSFERRED_SELECTOR: [u8; 4] = [0x50, 0xed, 0x06, 0x4a];

const ORDER_TO_OFF: u64 = 80;
const ORDER_CONTENT_OFF: u64 = 112;
const ORDER_SCHEME_OFF: u64 = 144;
const ORDER_PTR_OFF: u64 = 152;
const ORDER_ID_OFF: u64 = 160;

const TRANSFER_TO_OFF: u64 = 80;
const TRANSFER_ID_OFF: u64 = 112;

const SUPPLY_SLOT: u64 = 4;
const OWNER_OF_BASE: u64 = 1 << 40;
const HOLDINGS_BASE: u64 = (1 << 40) + (1 << 32);
const CONTENT_BASE: u64 = (1 << 40) + (2 << 32);

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
        .ok_or("usage: qcollectible_e2e <gateway_url> <container_hex_file>")?;
    let container_file = args
        .next()
        .ok_or("usage: qcollectible_e2e <gateway_url> <container_hex_file>")?;

    let client = Client::new(url);
    let info = client.node_info()?;
    let fee = info.transfer_fee;
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
    let content_1 = [0xC1u8; 32];
    let content_2 = [0xC2u8; 32];

    println!("admin/owner A  {a}");
    println!("owner B        {b}");
    println!("non owner      {stranger}");
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
        &[DeployParam::Address(a_id)],
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
    for (i, want) in a_id.chunks(8).enumerate() {
        if client.contract_scalar(&contract, i as u64)?
            != u64::from_be_bytes(want.try_into().unwrap())
        {
            return Err(format!("admin slot {i} is not A"));
        }
    }
    if client.contract_scalar(&contract, SUPPLY_SLOT)? != 0 {
        return Err("supply did not start at zero".into());
    }
    println!("[deploy] admin is A in full, supply starts at zero");

    println!("\n--- mint two collectibles to A ---");
    mint(
        &client,
        &contract,
        &OWNER_A_SEED,
        1,
        &a_id,
        &content_1,
        fee,
        "A",
    )?;
    if supply(&client, &contract)? != 1 || holding(&client, &contract, &a_id)? != 1 {
        return Err("mint of id 1 did not bump supply and A's holding to one".into());
    }
    assert_owner(&client, &contract, 1, &a_id, "id 1 owned by A in full")?;
    if read_addr_value(&client, &contract, CONTENT_BASE, &id_key(1))? != content_1 {
        return Err("content_of[1] did not read back the full content reference".into());
    }
    println!("[mint 1] supply 1, A holds 1, owner and content read back in full");

    mint(
        &client,
        &contract,
        &OWNER_A_SEED,
        2,
        &a_id,
        &content_2,
        fee,
        "A",
    )?;
    if supply(&client, &contract)? != 2 || holding(&client, &contract, &a_id)? != 2 {
        return Err("mint of id 2 did not bump supply to two and A's holding to two".into());
    }
    assert_owner(&client, &contract, 2, &a_id, "id 2 owned by A in full")?;
    assert_owner(
        &client,
        &contract,
        1,
        &a_id,
        "id 1 still owned by A, independent of id 2",
    )?;
    println!("[mint 2] supply 2, A holds 2, id 1 and id 2 owners are independent");

    println!("\n--- a non admin cannot mint ---");
    let supply_before = supply(&client, &contract)?;
    let (bad_tx, bad_out, bad_order) = mint_call(
        &client,
        &contract,
        &STRANGER_SEED,
        &STRANGER_SEED,
        3,
        &stranger_id,
        &content_1,
        fee,
    )?;
    accepted(&bad_out, "non admin mint")?;
    let bad_height = poll_finality(&client, &bad_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &id_key(3))? != [0u8; 32]
        || supply(&client, &contract)? != supply_before
        || find_event(&client, &contract, MINTED_SELECTOR, bad_height)?.is_some()
    {
        return Err("a non admin minted a collectible, the admin binding failed".into());
    }
    println!("[neg mint] a validly signed order by {} (not the admin) was refused: id 3 unminted, supply unchanged, no event", hex(&bad_order.signer));

    println!("\n--- a non owner cannot transfer ---");
    let (bt_tx, bt_out) = transfer_call(&client, &contract, &OWNER_B_SEED, 1, &b_id, fee)?;
    accepted(&bt_out, "non owner transfer")?;
    let bt_height = poll_finality(&client, &bt_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &id_key(1))? != a_id
        || find_event(&client, &contract, TRANSFERRED_SELECTOR, bt_height)?.is_some()
    {
        return Err("a non owner transferred a collectible it does not own".into());
    }
    println!("[neg xfer] B does not own id 1: reverted, owner still A, no event");

    println!("\n--- transfer id 1 from A to B moves the whole owner ---");
    let (xfer_tx, xfer_out) = transfer_call(&client, &contract, &OWNER_A_SEED, 1, &b_id, fee)?;
    accepted(&xfer_out, "transfer A to B")?;
    let xfer_height = poll_finality(&client, &xfer_tx.tx_id)?;
    assert_owner(
        &client,
        &contract,
        1,
        &b_id,
        "id 1 owned by B in full after transfer",
    )?;
    if holding(&client, &contract, &a_id)? != 1 || holding(&client, &contract, &b_id)? != 1 {
        return Err("the holding counts did not move A 2->1 and B 0->1".into());
    }
    assert_owner(
        &client,
        &contract,
        2,
        &a_id,
        "id 2 still owned by A, untouched by the move of id 1",
    )?;
    let evt = find_event(&client, &contract, TRANSFERRED_SELECTOR, xfer_height)?
        .ok_or("no Transferred event")?;
    if word_at(&evt, 0)? != 1 || addr_at(&evt, 8)? != a_id || addr_at(&evt, 40)? != b_id {
        return Err("the Transferred event did not carry id 1, the whole prior owner A, and the whole new owner B".into());
    }
    println!("[transfer] id 1 A -> B in full; A holds 1, B holds 1; id 2 unaffected");

    println!("\n--- after transfer, A cannot control id 1 and B can ---");
    let (arj_tx, arj_out) = transfer_call(&client, &contract, &OWNER_A_SEED, 1, &a_id, fee)?;
    accepted(&arj_out, "prior owner transfer")?;
    let arj_height = poll_finality(&client, &arj_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &id_key(1))? != b_id
        || find_event(&client, &contract, TRANSFERRED_SELECTOR, arj_height)?.is_some()
    {
        return Err("the prior owner A moved id 1 after the transfer".into());
    }
    println!("[neg2a] prior owner A could not transfer id 1 after the move: reverted, owner still B, no event");

    let (brj_tx, brj_out) = transfer_call(&client, &contract, &OWNER_B_SEED, 1, &stranger_id, fee)?;
    accepted(&brj_out, "new owner transfer")?;
    let brj_height = poll_finality(&client, &brj_tx.tx_id)?;
    assert_owner(
        &client,
        &contract,
        1,
        &stranger_id,
        "id 1 owned by the stranger in full after B's transfer",
    )?;
    if holding(&client, &contract, &b_id)? != 0 || holding(&client, &contract, &stranger_id)? != 1 {
        return Err("B's transfer did not move the holding counts B 1->0 and stranger 0->1".into());
    }
    find_event(&client, &contract, TRANSFERRED_SELECTOR, brj_height)?
        .ok_or("no Transferred event for the new owner")?;
    println!("[neg2b] new owner B moved id 1 to the stranger in full; B holds 0, stranger holds 1");
    println!("[neg2 ] PROOF: the transfer moved the whole binding, the prior owner is gone and the new owner holds it");

    Ok(())
}

fn mint(
    client: &Client,
    contract: &str,
    admin_seed: &[u8; 32],
    id: u64,
    to: &[u8; 32],
    content: &[u8; 32],
    fee: u128,
    who: &str,
) -> Result<(), String> {
    let (tx, out, order) = mint_call(
        client, contract, admin_seed, admin_seed, id, to, content, fee,
    )?;
    accepted(&out, "mint")?;
    let height = poll_finality(client, &tx.tx_id)?;
    let evt = find_event(client, contract, MINTED_SELECTOR, height)?.ok_or("no Minted event")?;
    if word_at(&evt, 0)? != id || addr_at(&evt, 8)? != *to || addr_at(&evt, 40)? != *content {
        return Err(
            "the Minted event did not carry the id, the whole recipient, and the whole content"
                .into(),
        );
    }
    println!(
        "\n[mint {id}] tx {} finalised at height {height}, signed by {} ({who})",
        tx.tx_id,
        hex(&order.signer)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mint_call(
    client: &Client,
    contract: &str,
    caller_seed: &[u8; 32],
    admin_seed: &[u8; 32],
    id: u64,
    to: &[u8; 32],
    content: &[u8; 32],
    fee: u128,
) -> Result<
    (
        qcore::SignedTransfer,
        Submit,
        qcore::contract::SignedOrderCall,
    ),
    String,
> {
    client.call_typed_order(
        caller_seed,
        0,
        contract,
        MINT_SELECTOR,
        ORDER_SCHEME_OFF,
        ORDER_PTR_OFF,
        qcore::contract::DEFAULT_REGION_OFFSET,
        &[
            FieldArg {
                offset: ORDER_ID_OFF,
                value: FieldValue::Word(id),
            },
            FieldArg {
                offset: ORDER_TO_OFF,
                value: FieldValue::Address(*to),
            },
            FieldArg {
                offset: ORDER_CONTENT_OFF,
                value: FieldValue::Address(*content),
            },
        ],
        admin_seed,
        0,
        0,
        None,
        METER,
        fee,
    )
}

fn transfer_call(
    client: &Client,
    contract: &str,
    caller_seed: &[u8; 32],
    id: u64,
    to: &[u8; 32],
    fee: u128,
) -> Result<(qcore::SignedTransfer, Submit), String> {
    let args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg {
                offset: TRANSFER_TO_OFF,
                value: FieldValue::Address(*to),
            },
            FieldArg {
                offset: TRANSFER_ID_OFF,
                value: FieldValue::Word(id),
            },
        ],
    )?;
    client.call(caller_seed, 0, contract, args, METER, fee)
}

fn supply(client: &Client, contract: &str) -> Result<u64, String> {
    client.contract_scalar(contract, SUPPLY_SLOT)
}

fn holding(client: &Client, contract: &str, who: &[u8; 32]) -> Result<u64, String> {
    client.contract_map(contract, HOLDINGS_BASE, who)
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
        let word = qcore::contract::storage_value(&slots, &addr_word_key(base, key, i));
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    Ok(out)
}

fn assert_owner(
    client: &Client,
    contract: &str,
    id: u64,
    want: &[u8; 32],
    what: &str,
) -> Result<(), String> {
    let got = read_addr_value(client, contract, OWNER_OF_BASE, &id_key(id))?;
    if &got != want {
        return Err(format!(
            "{what}: owner_of[{id}] reads {} not {}",
            hex(&got),
            hex(want)
        ));
    }
    println!("    [owner] {what}: {}", hex(&got));
    Ok(())
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
            TxStatus::Finalised { height, .. } => return Ok(height),
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
