use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qcore::contract::{DeployParam, FieldArg, FieldValue};
use qcore::{account_address, Client, Submit, TxStatus};

const DEPLOYER_SEED: [u8; 32] = [11u8; 32];
const HOLDER2_SEED: [u8; 32] = [33u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

const REGISTER_SELECTOR: [u8; 4] = [0x48, 0xe0, 0x4e, 0xf3];
const RENEW_SELECTOR: [u8; 4] = [0x31, 0x23, 0x6b, 0x4a];
const SET_RESOLVED_SELECTOR: [u8; 4] = [0x4b, 0x9d, 0x69, 0x8b];
const TRANSFER_SELECTOR: [u8; 4] = [0xe9, 0xf4, 0x49, 0x6d];
const WITHDRAW_SELECTOR: [u8; 4] = [0x46, 0x50, 0x21, 0x19];

const REGISTERED_SELECTOR: [u8; 4] = [0x73, 0x1e, 0x5e, 0x42];
const RENEWED_SELECTOR: [u8; 4] = [0x33, 0x13, 0xfc, 0xaf];
const RESOLVED_SELECTOR: [u8; 4] = [0x7e, 0x14, 0xf4, 0xdc];
const TRANSFERRED_SELECTOR: [u8; 4] = [0xaa, 0x54, 0x91, 0x82];
const SWEPT_SELECTOR: [u8; 4] = [0x98, 0xa2, 0xa3, 0x0e];

const NAME_OFF: u64 = 72;
const UNTIL_OFF: u64 = 104;
const YEARS_OFF: u64 = 104;
const TARGET_OFF: u64 = 104;
const TO_OFF: u64 = 104;
const WITHDRAW_SCHEME_OFF: u64 = 72;
const WITHDRAW_PTR_OFF: u64 = 80;
const WITHDRAW_AMOUNT_OFF: u64 = 88;

const PURCHASE_FEE_SLOT: u64 = 4;
const RENEWAL_FEE_SLOT: u64 = 5;
const VAULT_SLOT: u64 = 6;
const REGISTERED_BASE: u64 = 1 << 40;
const EXPIRY_BASE: u64 = (1 << 40) + (1 << 32);
const OWNERS_BASE: u64 = (1 << 40) + (2 << 32);
const RESOLVED_BASE: u64 = (1 << 40) + (3 << 32);

const YEAR_SECONDS: u64 = 31_536_000;
const PURCHASE_FEE: u64 = 5_000;
const RENEWAL_FEE: u64 = 1_000;
const METER: u64 = 12_000_000;
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
    let url = args.next().ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;
    let container_file = args.next().ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;

    let client = Client::new(url);
    let info = client.node_info()?;
    let fee = info.transfer_fee;
    println!("network {} at height {}, fee {} {}", info.chain_id, info.head_height, fee, info.denomination);

    let q1 = account_address(&DEPLOYER_SEED, 0);
    let q2 = account_address(&HOLDER2_SEED, 0);
    let stranger = account_address(&STRANGER_SEED, 0);
    let q1_id = address_payload(&q1)?;
    let q2_id = address_payload(&q2)?;
    let stranger_id = address_payload(&stranger)?;

    let jeff = name_key("Jeff.Q")?;
    let mike = name_key("Mike.Q")?;

    let account = client.account(&q1)?;
    println!("admin/owner Q1 {q1}");
    println!("  nonce {} balance {} has_key {}", account.nonce, account.balance, account.has_key);
    println!("second owner Q2 {q2}");
    println!("non owner      {stranger}");
    if !account.has_key {
        return Err("Q1 is not a funded keyed genesis account, it cannot sign".into());
    }

    let container = from_hex(std::fs::read_to_string(&container_file).map_err(|e| format!("reading {container_file}: {e}"))?.trim())?;
    let (deploy_tx, deploy_out, contract) = client.deploy_with_params(
        &DEPLOYER_SEED,
        0,
        &container,
        &[DeployParam::Address(q1_id), DeployParam::U64(PURCHASE_FEE), DeployParam::U64(RENEWAL_FEE)],
        METER,
        fee,
    )?;
    accepted(&deploy_out, "deploy")?;
    let deploy_height = poll_finality(&client, &deploy_tx.tx_id)?;
    println!("\n[deploy] tx {} finalised at height {deploy_height}", deploy_tx.tx_id);
    println!("[deploy] contract {contract}");
    if client.storage(&contract)?.is_empty() {
        return Err("the contract deployed no storage, the genesis constructor did not run".into());
    }
    for (i, want) in q1_id.chunks(8).enumerate() {
        let got = client.contract_scalar(&contract, i as u64)?;
        if got != u64::from_be_bytes(want.try_into().unwrap()) {
            return Err(format!("admin slot {i} is {got}, not Q1"));
        }
    }
    let purchase0 = client.contract_scalar(&contract, PURCHASE_FEE_SLOT)?;
    let renewal0 = client.contract_scalar(&contract, RENEWAL_FEE_SLOT)?;
    let vault0 = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[deploy] admin is Q1, purchase_fee {purchase0}, renewal_fee {renewal0}, vault {vault0}");
    if purchase0 != PURCHASE_FEE || renewal0 != RENEWAL_FEE || vault0 != 0 {
        return Err("the deploy parameters did not land in state".into());
    }

    let mut fees_taken = 0u64;
    let mut swept = 0u64;
    conservation(&client, &contract, fees_taken, swept, "after deploy")?;

    let until = now_seconds() + YEAR_SECONDS;

    let jeff_height = register(&client, &DEPLOYER_SEED, &contract, jeff, until, fee, "Jeff.Q", "Q1")?;
    let reg_owner = client.contract_map(&contract, OWNERS_BASE, &q1_id)?;
    let reg_taken = client.contract_map(&contract, REGISTERED_BASE, &jeff)?;
    let reg_expiry = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    println!("[register Jeff.Q] registered {reg_taken}, owner Q1 {reg_owner}, expiry {reg_expiry}");
    if reg_taken != 1 || reg_owner != 1 || reg_expiry != until {
        return Err("Jeff.Q did not register to Q1 with its expiry".into());
    }
    let registered_evt = find_event(&client, &contract, REGISTERED_SELECTOR, jeff_height)?.ok_or("no Registered event")?;
    if word_at(&registered_evt, 2)? != until {
        return Err("the Registered event carried the wrong expiry".into());
    }
    fees_taken += PURCHASE_FEE;
    let vault_after_jeff = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[register Jeff.Q] vault {vault0} -> {vault_after_jeff}, Registered event expiry {until}");
    conservation(&client, &contract, fees_taken, swept, "after Jeff.Q register")?;

    let _ = register(&client, &DEPLOYER_SEED, &contract, mike, until, fee, "Mike.Q", "Q1")?;
    fees_taken += PURCHASE_FEE;
    let vault_after_mike = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[register Mike.Q] vault {vault_after_jeff} -> {vault_after_mike}, both names owned by Q1");
    conservation(&client, &contract, fees_taken, swept, "after Mike.Q register")?;

    let years = 2u64;
    let renew_args = qcore::contract::build_call_args(
        RENEW_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: YEARS_OFF, value: FieldValue::Word(years) },
        ],
    )?;
    let (renew_tx, renew_out) = client.call(&DEPLOYER_SEED, 0, &contract, renew_args, METER, fee)?;
    accepted(&renew_out, "renew")?;
    let renew_height = poll_finality(&client, &renew_tx.tx_id)?;
    let expiry_renewed = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    let expect_expiry = until + years * YEAR_SECONDS;
    println!("\n[renew Jeff.Q] {years} years, expiry {reg_expiry} -> {expiry_renewed}");
    if expiry_renewed != expect_expiry {
        return Err(format!("renew did not extend expiry to {expect_expiry}, got {expiry_renewed}"));
    }
    let renewed_evt = find_event(&client, &contract, RENEWED_SELECTOR, renew_height)?.ok_or("no Renewed event")?;
    if word_at(&renewed_evt, 1)? != years {
        return Err("the Renewed event carried the wrong term".into());
    }
    fees_taken += RENEWAL_FEE * years;
    let vault_after_renew = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[renew Jeff.Q] vault {vault_after_mike} -> {vault_after_renew}");
    conservation(&client, &contract, fees_taken, swept, "after Jeff.Q renew")?;

    let resolved_before = client.contract_map(&contract, RESOLVED_BASE, &mike)?;
    let resolve_args = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(mike) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(q2_id) },
        ],
    )?;
    let (resolve_tx, resolve_out) = client.call(&DEPLOYER_SEED, 0, &contract, resolve_args, METER, fee)?;
    accepted(&resolve_out, "set_resolved")?;
    let resolve_height = poll_finality(&client, &resolve_tx.tx_id)?;
    let resolved_after = client.contract_map(&contract, RESOLVED_BASE, &mike)?;
    let target_word = u64::from_be_bytes(q2_id[0..8].try_into().unwrap());
    println!("\n[set_resolved Mike.Q] resolved {resolved_before} -> {resolved_after}, target Q2");
    if resolved_after != target_word {
        return Err("Mike.Q did not resolve to Q2".into());
    }
    find_event(&client, &contract, RESOLVED_SELECTOR, resolve_height)?.ok_or("no Resolved event")?;
    conservation(&client, &contract, fees_taken, swept, "after set_resolved")?;
    println!("[set_resolved Mike.Q] PROOF: owner Q1 set the resolved target, Resolved event recorded");

    let owner_q2_before = client.contract_map(&contract, OWNERS_BASE, &q2_id)?;
    let transfer_args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(q2_id) },
        ],
    )?;
    let (transfer_tx, transfer_out) = client.call(&DEPLOYER_SEED, 0, &contract, transfer_args, METER, fee)?;
    accepted(&transfer_out, "transfer")?;
    let transfer_height = poll_finality(&client, &transfer_tx.tx_id)?;
    let owner_q2_after = client.contract_map(&contract, OWNERS_BASE, &q2_id)?;
    println!("\n[transfer Jeff.Q] owner Q2 {owner_q2_before} -> {owner_q2_after}");
    if owner_q2_after != 1 {
        return Err("transfer did not make Q2 an owner".into());
    }
    find_event(&client, &contract, TRANSFERRED_SELECTOR, transfer_height)?.ok_or("no Transferred event")?;
    conservation(&client, &contract, fees_taken, swept, "after transfer")?;
    println!("[transfer Jeff.Q] PROOF: ownership moved to Q2, Transferred event recorded");

    println!("\n--- security ---");

    let bad_resolve = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(stranger_id) },
        ],
    )?;
    let (bad_r_tx, bad_r_out) = client.call(&STRANGER_SEED, 0, &contract, bad_resolve, METER, fee)?;
    accepted(&bad_r_out, "non owner set_resolved")?;
    let bad_r_height = poll_finality(&client, &bad_r_tx.tx_id)?;
    let resolved_jeff = client.contract_map(&contract, RESOLVED_BASE, &jeff)?;
    println!("\n[non owner set_resolved] a non owner tried to set Jeff.Q, height {bad_r_height}");
    if resolved_jeff != 0 || find_event(&client, &contract, RESOLVED_SELECTOR, bad_r_height)?.is_some() {
        return Err("a non owner set the resolved target, the owner guard failed".into());
    }
    println!("[non owner set_resolved] PROOF: refused, Jeff.Q resolved still {resolved_jeff} and no event");

    let bad_transfer = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(stranger_id) },
        ],
    )?;
    let (bad_t_tx, bad_t_out) = client.call(&STRANGER_SEED, 0, &contract, bad_transfer, METER, fee)?;
    accepted(&bad_t_out, "non owner transfer")?;
    let bad_t_height = poll_finality(&client, &bad_t_tx.tx_id)?;
    let owner_stranger = client.contract_map(&contract, OWNERS_BASE, &stranger_id)?;
    println!("[non owner transfer] a non owner tried to transfer Jeff.Q, height {bad_t_height}");
    if owner_stranger != 0 || find_event(&client, &contract, TRANSFERRED_SELECTOR, bad_t_height)?.is_some() {
        return Err("a non owner transferred a name, the owner guard failed".into());
    }
    println!("[non owner transfer] PROOF: refused, the non owner is still not an owner and no event");

    let taken_before = client.contract_map(&contract, REGISTERED_BASE, &jeff)?;
    let expiry_before = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    let vault_before_retake = client.contract_scalar(&contract, VAULT_SLOT)?;
    let retake = qcore::contract::build_call_args(
        REGISTER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: UNTIL_OFF, value: FieldValue::Word(until + 10 * YEAR_SECONDS) },
        ],
    )?;
    let (retake_tx, retake_out) = client.call(&STRANGER_SEED, 0, &contract, retake, METER, fee)?;
    accepted(&retake_out, "retake")?;
    let retake_height = poll_finality(&client, &retake_tx.tx_id)?;
    let expiry_after = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    let owner_stranger2 = client.contract_map(&contract, OWNERS_BASE, &stranger_id)?;
    let vault_after_retake = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("\n[retake Jeff.Q] a stranger tried to register an unexpired Jeff.Q, height {retake_height}");
    if expiry_after != expiry_before || owner_stranger2 != 0 || vault_after_retake != vault_before_retake
        || find_event(&client, &contract, REGISTERED_SELECTOR, retake_height)?.is_some()
    {
        return Err("an unexpired name was re-registered, the expiry guard failed".into());
    }
    println!("[retake Jeff.Q] PROOF: refused, expiry unchanged at {expiry_after}, no fee taken, no event");
    if taken_before != 1 {
        return Err("Jeff.Q registration was lost".into());
    }
    conservation(&client, &contract, fees_taken, swept, "after refused retake")?;

    let vault_before_bad_sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    let (bad_w_tx, bad_w_out, bad_w_order) = client.call_typed_order(
        &STRANGER_SEED,
        0,
        &contract,
        WITHDRAW_SELECTOR,
        WITHDRAW_SCHEME_OFF,
        WITHDRAW_PTR_OFF,
        REGION_OFF,
        &[FieldArg { offset: WITHDRAW_AMOUNT_OFF, value: FieldValue::Word(vault_before_bad_sweep) }],
        &STRANGER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&bad_w_out, "non admin withdraw")?;
    let bad_w_height = poll_finality(&client, &bad_w_tx.tx_id)?;
    let vault_after_bad_sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("\n[non admin withdraw] a non admin signed a sweep, signer {}, height {bad_w_height}", hex(&bad_w_order.signer));
    if vault_after_bad_sweep != vault_before_bad_sweep || find_event(&client, &contract, SWEPT_SELECTOR, bad_w_height)?.is_some() {
        return Err("a non admin swept the vault, the admin binding failed".into());
    }
    println!("[non admin withdraw] PROOF: refused, vault unchanged at {vault_after_bad_sweep} and no event");
    conservation(&client, &contract, fees_taken, swept, "after refused withdraw")?;

    let sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    let (w_tx, w_out, w_order) = client.call_typed_order(
        &DEPLOYER_SEED,
        0,
        &contract,
        WITHDRAW_SELECTOR,
        WITHDRAW_SCHEME_OFF,
        WITHDRAW_PTR_OFF,
        REGION_OFF,
        &[FieldArg { offset: WITHDRAW_AMOUNT_OFF, value: FieldValue::Word(sweep) }],
        &DEPLOYER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&w_out, "admin withdraw")?;
    let w_height = poll_finality(&client, &w_tx.tx_id)?;
    let vault_final = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("\n[withdraw] admin swept {sweep}, signer {}, nonce {}", hex(&w_order.signer), w_order.nonce);
    println!("[withdraw] vault {sweep} -> {vault_final}");
    if vault_final != 0 {
        return Err(format!("the admin sweep left {vault_final} in the vault"));
    }
    let swept_evt = find_event(&client, &contract, SWEPT_SELECTOR, w_height)?.ok_or("no Swept event")?;
    if word_at(&swept_evt, 0)? != sweep {
        return Err("the Swept event carried the wrong amount".into());
    }
    swept += sweep;
    conservation(&client, &contract, fees_taken, swept, "after admin withdraw")?;
    println!("[withdraw] PROOF: admin swept the collected fees, vault and swept still sum to the fees taken");

    Ok(())
}

fn register(
    client: &Client,
    seed: &[u8; 32],
    contract: &str,
    name: [u8; 32],
    until: u64,
    fee: u128,
    label: &str,
    owner: &str,
) -> Result<u64, String> {
    let args = qcore::contract::build_call_args(
        REGISTER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(name) },
            FieldArg { offset: UNTIL_OFF, value: FieldValue::Word(until) },
        ],
    )?;
    let (tx, out) = client.call(seed, 0, contract, args, METER, fee)?;
    accepted(&out, "register")?;
    let height = poll_finality(client, &tx.tx_id)?;
    println!("\n[register {label}] tx {} finalised at height {height}, owner {owner}", tx.tx_id);
    Ok(height)
}

fn conservation(client: &Client, contract: &str, fees_taken: u64, swept: u64, at: &str) -> Result<(), String> {
    let vault = client.contract_scalar(contract, VAULT_SLOT)?;
    println!("    [conservation {at}] vault={vault} swept={swept} fees_taken={fees_taken}");
    if vault + swept != fees_taken {
        return Err(format!("conservation broke {at}: vault {vault} plus swept {swept} != fees taken {fees_taken}"));
    }
    Ok(())
}

fn name_key(name: &str) -> Result<[u8; 32], String> {
    if !name.ends_with(".Q") {
        return Err(format!("a domain must end with .Q, got {name}"));
    }
    Ok(qtv_crypto::sha3::sha3_256(name.as_bytes()))
}

fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn word_at(data: &[u8], word_index: usize) -> Result<u64, String> {
    let start = word_index * 8;
    data.get(start..start + 8)
        .ok_or("the event payload is shorter than its word".to_string())
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
    for _ in 0..240 {
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
