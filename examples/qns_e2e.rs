use std::thread::sleep;
use std::time::Duration;

use qcore::contract::{name_key, storage_value, DeployParam, FieldArg, FieldValue};
use qcore::{account_address, Client, Submit, TxStatus};

const OWNER_A_SEED: [u8; 32] = [11u8; 32];
const OWNER_B_SEED: [u8; 32] = [33u8; 32];
const STRANGER_SEED: [u8; 32] = [22u8; 32];

const REGISTER_SELECTOR: [u8; 4] = [0x2d, 0xfb, 0xa5, 0xfc];
const RENEW_SELECTOR: [u8; 4] = [0x99, 0x76, 0x10, 0xf3];
const SET_RESOLVED_SELECTOR: [u8; 4] = [0xea, 0x5f, 0x21, 0x92];
const TRANSFER_SELECTOR: [u8; 4] = [0xf7, 0xe4, 0xde, 0x7b];
const WITHDRAW_SELECTOR: [u8; 4] = [0x46, 0x50, 0x21, 0x19];

const REGISTERED_SELECTOR: [u8; 4] = [0x51, 0x6a, 0x04, 0x2e];
const RENEWED_SELECTOR: [u8; 4] = [0x0c, 0x22, 0xfc, 0x20];
const RESOLVED_SELECTOR: [u8; 4] = [0x7e, 0x14, 0xf4, 0xdc];
const TRANSFERRED_SELECTOR: [u8; 4] = [0xaa, 0x54, 0x91, 0x82];
const SWEPT_SELECTOR: [u8; 4] = [0x98, 0xa2, 0xa3, 0x0e];

const NAME_OFF: u64 = 72;
const YEARS_OFF: u64 = 112;
const TARGET_OFF: u64 = 112;
const TO_OFF: u64 = 112;
const WITHDRAW_SCHEME_OFF: u64 = 72;
const WITHDRAW_PTR_OFF: u64 = 80;
const WITHDRAW_AMOUNT_OFF: u64 = 88;

const BASE3_SLOT: u64 = 4;
const BASE4_SLOT: u64 = 5;
const BASE5_SLOT: u64 = 6;
const GRACE_SLOT: u64 = 7;
const AUCTION_SLOT: u64 = 8;
const START_PREMIUM_SLOT: u64 = 9;
const INTERVAL_SLOT: u64 = 10;
const VAULT_SLOT: u64 = 11;
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
    let url = args.next().ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;
    let container_file = args.next().ok_or("usage: qns_e2e <gateway_url> <container_hex_file>")?;

    let client = Client::new(url);
    let info = client.node_info()?;
    let fee = info.transfer_fee;
    println!("network {} at height {}, fee {} {}", info.chain_id, info.head_height, fee, info.denomination);

    let a = account_address(&OWNER_A_SEED, 0);
    let b = account_address(&OWNER_B_SEED, 0);
    let stranger = account_address(&STRANGER_SEED, 0);
    let a_id = address_payload(&a)?;
    let b_id = address_payload(&b)?;
    let stranger_id = address_payload(&stranger)?;

    println!("admin/owner A  {a}");
    println!("owner B        {b}");
    println!("non owner      {stranger}");
    for (label, addr) in [("A", &a), ("B", &b)] {
        let account = client.account(addr)?;
        println!("  {label} nonce {} balance {} has_key {}", account.nonce, account.balance, account.has_key);
        if !account.has_key {
            return Err(format!("{label} is not a funded keyed genesis account, it cannot sign"));
        }
    }

    let container = from_hex(std::fs::read_to_string(&container_file).map_err(|e| format!("reading {container_file}: {e}"))?.trim())?;
    let (deploy_tx, deploy_out, contract) = client.deploy_with_params(
        &OWNER_A_SEED,
        0,
        &container,
        &[
            DeployParam::Address(a_id),
            DeployParam::U64(BASE_3),
            DeployParam::U64(BASE_4),
            DeployParam::U64(BASE_5_PLUS),
            DeployParam::U64(GRACE_PERIOD),
            DeployParam::U64(AUCTION_DURATION),
            DeployParam::U64(START_PREMIUM),
            DeployParam::U64(INTERVAL),
        ],
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
    for (i, want) in a_id.chunks(8).enumerate() {
        let got = client.contract_scalar(&contract, i as u64)?;
        if got != u64::from_be_bytes(want.try_into().unwrap()) {
            return Err(format!("admin slot {i} is {got}, not A"));
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
            return Err(format!("deploy parameter {name} landed as {got}, expected {want}"));
        }
    }
    if client.contract_scalar(&contract, VAULT_SLOT)? != 0 {
        return Err("the vault did not start empty".into());
    }
    println!(
        "[deploy] admin is A; tiers 3/4/5+ = {BASE_3}/{BASE_4}/{BASE_5_PLUS}; grace {} days, auction {} days, start_premium {START_PREMIUM}, interval {} day",
        GRACE_PERIOD / DAY, AUCTION_DURATION / DAY, INTERVAL / DAY
    );

    let mut fees_taken = 0u64;
    let mut swept = 0u64;
    conservation(&client, &contract, fees_taken, swept, "after deploy")?;

    println!("\n--- tier pricing: one year each, distinct label lengths ---");
    // A three character label at base_3.
    register(&client, &OWNER_A_SEED, &contract, "sol", 1, fee, &a_id)?;
    fees_taken += BASE_3;
    let e_sol = expiry_of(&client, &contract, "sol")?;
    if e_sol % DAY != 0 || e_sol < YEAR {
        return Err(format!("sol expiry {e_sol} is not a whole day at least a year out"));
    }
    conservation(&client, &contract, fees_taken, swept, "after sol (3 char, base_3)")?;
    tier_charged(&client, &contract, BASE_3, "sol", 3)?;

    // A four character label at base_4.
    register(&client, &OWNER_A_SEED, &contract, "jeff", 1, fee, &a_id)?;
    fees_taken += BASE_4;
    conservation(&client, &contract, fees_taken, swept, "after jeff (4 char, base_4)")?;
    tier_charged(&client, &contract, BASE_4, "jeff", 4)?;

    // A five character label owned by B at base_5_plus.
    register(&client, &OWNER_B_SEED, &contract, "alice", 1, fee, &b_id)?;
    fees_taken += BASE_5_PLUS;
    conservation(&client, &contract, fees_taken, swept, "after alice (5 char, base_5_plus)")?;
    tier_charged(&client, &contract, BASE_5_PLUS, "alice", 5)?;
    println!("[tiers] PROOF: base_3 {BASE_3}, base_4 {BASE_4}, base_5_plus {BASE_5_PLUS} each hit the vault by label length");

    println!("\n--- renew within grace ---");
    let jeff_before = expiry_of(&client, &contract, "jeff")?;
    let years = 2u64;
    let renew_args = qcore::contract::build_call_args(
        RENEW_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: YEARS_OFF, value: FieldValue::Word(years) },
        ],
    )?;
    let (renew_tx, renew_out) = client.call(&OWNER_A_SEED, 0, &contract, renew_args, METER, fee)?;
    accepted(&renew_out, "renew")?;
    let renew_height = poll_finality(&client, &renew_tx.tx_id)?;
    let jeff_after = expiry_of(&client, &contract, "jeff")?;
    println!("[renew jeff] {years} years, expiry {jeff_before} -> {jeff_after}");
    if jeff_after != jeff_before + years * YEAR {
        return Err(format!("renew did not add {years} whole years, {jeff_before} -> {jeff_after}"));
    }
    fees_taken += BASE_4 * years;
    let renewed_evt = find_event(&client, &contract, RENEWED_SELECTOR, renew_height)?.ok_or("no Renewed event")?;
    if !label_window_is(&renewed_evt, "jeff") || word_at(&renewed_evt, 4)? != jeff_after || word_at(&renewed_evt, 5)? != years {
        return Err("the Renewed event did not carry the label, the new expiry, and the term".into());
    }
    conservation(&client, &contract, fees_taken, swept, "after jeff renew")?;
    println!("[renew jeff] PROOF: two whole years added, base_4 charged per year");

    println!("\n--- full 32 byte resolution ---");
    let target = b_id;
    let resolve_args = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(target) },
        ],
    )?;
    let (resolve_tx, resolve_out) = client.call(&OWNER_A_SEED, 0, &contract, resolve_args, METER, fee)?;
    accepted(&resolve_out, "set_resolved")?;
    let resolve_height = poll_finality(&client, &resolve_tx.tx_id)?;
    let reassembled = read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))?;
    if reassembled != target {
        return Err(format!("the reassembled resolution {} does not equal the full target {}", hex(&reassembled), hex(&target)));
    }
    let resolved_evt = find_event(&client, &contract, RESOLVED_SELECTOR, resolve_height)?.ok_or("no Resolved event")?;
    if addr_at(&resolved_evt, 64)? != target {
        return Err("the Resolved event did not carry the whole target".into());
    }
    println!("[set_resolved jeff] PROOF: all thirty two bytes of the target resolve back in full");
    conservation(&client, &contract, fees_taken, swept, "after set_resolved")?;

    println!("\n--- per name ownership negatives ---");
    // B is a registered owner (of alice) but does not own jeff.
    let b_resolve = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(stranger_id) },
        ],
    )?;
    let (br_tx, br_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve, METER, fee)?;
    accepted(&br_out, "B set_resolved of a name it does not own")?;
    let br_height = poll_finality(&client, &br_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != target
        || find_event(&client, &contract, RESOLVED_SELECTOR, br_height)?.is_some()
    {
        return Err("a registered owner set_resolved a name it does not own".into());
    }
    println!("[neg1a] B could not set_resolved jeff (owned by A): reverted, resolution unchanged, no event");

    let b_transfer = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(b_id) },
        ],
    )?;
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
    conservation(&client, &contract, fees_taken, swept, "after B's refused attempts")?;

    println!("\n--- transfer moves the binding in full ---");
    assert_owner(&client, &contract, "jeff", &a_id, "jeff owned by A before transfer")?;
    let transfer_args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(b_id) },
        ],
    )?;
    let (transfer_tx, transfer_out) = client.call(&OWNER_A_SEED, 0, &contract, transfer_args, METER, fee)?;
    accepted(&transfer_out, "transfer")?;
    let transfer_height = poll_finality(&client, &transfer_tx.tx_id)?;
    assert_owner(&client, &contract, "jeff", &b_id, "jeff owned by B in full after transfer")?;
    let transferred_evt = find_event(&client, &contract, TRANSFERRED_SELECTOR, transfer_height)?.ok_or("no Transferred event")?;
    if !label_window_is(&transferred_evt, "jeff") || addr_at(&transferred_evt, 32)? != a_id || addr_at(&transferred_evt, 64)? != b_id {
        return Err("the Transferred event did not carry the label and the whole prior and new owner".into());
    }
    println!("[transfer jeff] A -> B, owner_of[jeff] now reads B in full");

    // The prior owner A can no longer act on jeff; the new owner B can.
    let a_resolve_jeff = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(a_id) },
        ],
    )?;
    let (arj_tx, arj_out) = client.call(&OWNER_A_SEED, 0, &contract, a_resolve_jeff, METER, fee)?;
    accepted(&arj_out, "prior owner set_resolved")?;
    let arj_height = poll_finality(&client, &arj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != target
        || find_event(&client, &contract, RESOLVED_SELECTOR, arj_height)?.is_some()
    {
        return Err("the prior owner A set_resolved a transferred name".into());
    }
    println!("[neg2a] prior owner A could not set_resolved jeff after transfer: reverted, no event");

    let b_resolve_jeff = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("jeff") },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(stranger_id) },
        ],
    )?;
    let (brj_tx, brj_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve_jeff, METER, fee)?;
    accepted(&brj_out, "new owner set_resolved")?;
    let brj_height = poll_finality(&client, &brj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &name_key("jeff"))? != stranger_id {
        return Err("the new owner B could not set_resolved jeff".into());
    }
    find_event(&client, &contract, RESOLVED_SELECTOR, brj_height)?.ok_or("no Resolved event for the new owner")?;
    println!("[neg2b] new owner B set_resolved jeff to a full target and it reassembles in full");
    println!("[neg2 ] PROOF: transfer moved the binding, the prior owner is gone and the new owner holds it");
    conservation(&client, &contract, fees_taken, swept, "after ownership move proofs")?;

    println!("\n--- an unexpired name cannot be re-registered ---");
    let expiry_before = expiry_of(&client, &contract, "sol")?;
    let owner_before = read_addr_value(&client, &contract, OWNER_OF_BASE, &name_key("sol"))?;
    let vault_before = client.contract_scalar(&contract, VAULT_SLOT)?;
    let retake = qcore::contract::build_call_args(
        REGISTER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name("sol") },
            FieldArg { offset: YEARS_OFF, value: FieldValue::Word(5) },
        ],
    )?;
    let (retake_tx, retake_out) = client.call(&STRANGER_SEED, 0, &contract, retake, METER, fee)?;
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
    conservation(&client, &contract, fees_taken, swept, "after refused retake")?;

    println!("\n--- admin only sweep ---");
    let region_off = qcore::contract::DEFAULT_REGION_OFFSET;
    let vault_now = client.contract_scalar(&contract, VAULT_SLOT)?;
    let (bad_w_tx, bad_w_out, bad_w_order) = client.call_typed_order(
        &STRANGER_SEED,
        0,
        &contract,
        WITHDRAW_SELECTOR,
        WITHDRAW_SCHEME_OFF,
        WITHDRAW_PTR_OFF,
        region_off,
        &[FieldArg { offset: WITHDRAW_AMOUNT_OFF, value: FieldValue::Word(vault_now) }],
        &STRANGER_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&bad_w_out, "non admin withdraw")?;
    let bad_w_height = poll_finality(&client, &bad_w_tx.tx_id)?;
    if client.contract_scalar(&contract, VAULT_SLOT)? != vault_now
        || find_event(&client, &contract, SWEPT_SELECTOR, bad_w_height)?.is_some()
    {
        return Err("a non admin swept the vault, the admin binding failed".into());
    }
    println!("[neg4 ] PROOF: a non admin sweep signed by {} was refused, vault unchanged, no event", hex(&bad_w_order.signer));
    conservation(&client, &contract, fees_taken, swept, "after refused withdraw")?;

    let sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    let (w_tx, w_out, w_order) = client.call_typed_order(
        &OWNER_A_SEED,
        0,
        &contract,
        WITHDRAW_SELECTOR,
        WITHDRAW_SCHEME_OFF,
        WITHDRAW_PTR_OFF,
        region_off,
        &[FieldArg { offset: WITHDRAW_AMOUNT_OFF, value: FieldValue::Word(sweep) }],
        &OWNER_A_SEED,
        0,
        METER,
        fee,
    )?;
    accepted(&w_out, "admin withdraw")?;
    let w_height = poll_finality(&client, &w_tx.tx_id)?;
    let vault_final = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[withdraw] admin swept {sweep}, signer {}, nonce {}", hex(&w_order.signer), w_order.nonce);
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
    label: &str,
    years: u64,
    fee: u128,
    owner: &[u8; 32],
) -> Result<u64, String> {
    let vault_before = client.contract_scalar(contract, VAULT_SLOT)?;
    let args = qcore::contract::build_call_args(
        REGISTER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::name(label) },
            FieldArg { offset: YEARS_OFF, value: FieldValue::Word(years) },
        ],
    )?;
    let (tx, out) = client.call(seed, 0, contract, args, METER, fee)?;
    accepted(&out, "register")?;
    let height = poll_finality(client, &tx.tx_id)?;
    let vault_after = client.contract_scalar(contract, VAULT_SLOT)?;
    println!("\n[register {label}] tx {} finalised at height {height}, vault {vault_before} -> {vault_after}", tx.tx_id);
    assert_owner(client, contract, label, owner, &format!("{label} owned in full"))?;
    let evt = find_event(client, contract, REGISTERED_SELECTOR, height)?.ok_or("no Registered event")?;
    if !label_window_is(&evt, label) {
        return Err(format!("the Registered event did not carry the label window for {label}"));
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

fn tier_charged(client: &Client, contract: &str, want: u64, label: &str, len: usize) -> Result<(), String> {
    // The vault jump is proven by the running conservation total; here we restate the tier for the log.
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

fn conservation(client: &Client, contract: &str, fees_taken: u64, swept: u64, at: &str) -> Result<(), String> {
    let vault = client.contract_scalar(contract, VAULT_SLOT)?;
    println!("    [conservation {at}] vault={vault} swept={swept} fees_taken={fees_taken}");
    if vault + swept != fees_taken {
        return Err(format!("conservation broke {at}: vault {vault} plus swept {swept} != fees taken {fees_taken}"));
    }
    Ok(())
}

fn addr_word_key(base: u64, key: &[u8; 32], word: u64) -> [u8; 32] {
    let mut input = base.to_be_bytes().to_vec();
    input.extend_from_slice(key);
    input.extend_from_slice(&word.to_be_bytes());
    qtv_crypto::sha3::sha3_256(&input)
}

fn read_addr_value(client: &Client, contract: &str, base: u64, key: &[u8; 32]) -> Result<[u8; 32], String> {
    let slots = client.storage(contract)?;
    let mut out = [0u8; 32];
    for i in 0..4u64 {
        let word = storage_value(&slots, &addr_word_key(base, key, i));
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    Ok(out)
}

fn assert_owner(client: &Client, contract: &str, label: &str, want: &[u8; 32], what: &str) -> Result<(), String> {
    let got = read_addr_value(client, contract, OWNER_OF_BASE, &name_key(label))?;
    if &got != want {
        return Err(format!("{what}: owner_of reads {} not {}", hex(&got), hex(want)));
    }
    println!("    [owner] {what}: {}", hex(&got));
    Ok(())
}

fn label_window_is(data: &[u8], label: &str) -> bool {
    let bytes = label.as_bytes();
    data.len() >= 32 && &data[..bytes.len()] == bytes && data[bytes.len()..32].iter().all(|&b| b == 0)
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
