use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qcore::contract::{storage_value, DeployParam, FieldArg, FieldValue};
use qcore::{account_address, Client, Submit, TxStatus};

const OWNER_A_SEED: [u8; 32] = [11u8; 32];
const OWNER_B_SEED: [u8; 32] = [33u8; 32];
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
const OWNER_OF_BASE: u64 = (1 << 40) + (2 << 32);
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

    let a = account_address(&OWNER_A_SEED, 0);
    let b = account_address(&OWNER_B_SEED, 0);
    let stranger = account_address(&STRANGER_SEED, 0);
    let a_id = address_payload(&a)?;
    let b_id = address_payload(&b)?;
    let stranger_id = address_payload(&stranger)?;

    let jeff = name_key("Jeff.Q")?;
    let mike = name_key("Mike.Q")?;
    let bob = name_key("Bob.Q")?;

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
        &[DeployParam::Address(a_id), DeployParam::U64(PURCHASE_FEE), DeployParam::U64(RENEWAL_FEE)],
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
    let purchase0 = client.contract_scalar(&contract, PURCHASE_FEE_SLOT)?;
    let renewal0 = client.contract_scalar(&contract, RENEWAL_FEE_SLOT)?;
    let vault0 = client.contract_scalar(&contract, VAULT_SLOT)?;
    println!("[deploy] admin is A, purchase_fee {purchase0}, renewal_fee {renewal0}, vault {vault0}");
    if purchase0 != PURCHASE_FEE || renewal0 != RENEWAL_FEE || vault0 != 0 {
        return Err("the deploy parameters did not land in state".into());
    }

    let mut fees_taken = 0u64;
    let mut swept = 0u64;
    conservation(&client, &contract, fees_taken, swept, "after deploy")?;

    let until = now_seconds() + YEAR_SECONDS;

    // Jeff.Q and Mike.Q register to A, Bob.Q registers to B, so B is itself a registered owner.
    let jeff_height = register(&client, &OWNER_A_SEED, &contract, jeff, until, fee, "Jeff.Q", "A")?;
    assert_owner(&client, &contract, jeff, &a_id, "Jeff.Q owned by A in full")?;
    let reg_taken = client.contract_map(&contract, REGISTERED_BASE, &jeff)?;
    let reg_expiry = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    if reg_taken != 1 || reg_expiry != until {
        return Err("Jeff.Q did not register with its expiry".into());
    }
    let registered_evt = find_event(&client, &contract, REGISTERED_SELECTOR, jeff_height)?.ok_or("no Registered event")?;
    if addr_at(&registered_evt, 32)? != a_id {
        return Err("the Registered event did not carry the whole owner address".into());
    }
    if word_at(&registered_evt, 8)? != until {
        return Err("the Registered event carried the wrong expiry after the two full addresses".into());
    }
    fees_taken += PURCHASE_FEE;
    conservation(&client, &contract, fees_taken, swept, "after Jeff.Q register")?;

    let _ = register(&client, &OWNER_A_SEED, &contract, mike, until, fee, "Mike.Q", "A")?;
    assert_owner(&client, &contract, mike, &a_id, "Mike.Q owned by A in full")?;
    fees_taken += PURCHASE_FEE;
    conservation(&client, &contract, fees_taken, swept, "after Mike.Q register")?;

    let _ = register(&client, &OWNER_B_SEED, &contract, bob, until, fee, "Bob.Q", "B")?;
    assert_owner(&client, &contract, bob, &b_id, "Bob.Q owned by B in full")?;
    fees_taken += PURCHASE_FEE;
    println!("[register Bob.Q] B is now a registered owner of its own name");
    conservation(&client, &contract, fees_taken, swept, "after Bob.Q register")?;

    let years = 2u64;
    let renew_args = qcore::contract::build_call_args(
        RENEW_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(mike) },
            FieldArg { offset: YEARS_OFF, value: FieldValue::Word(years) },
        ],
    )?;
    let (renew_tx, renew_out) = client.call(&OWNER_A_SEED, 0, &contract, renew_args, METER, fee)?;
    accepted(&renew_out, "renew")?;
    let renew_height = poll_finality(&client, &renew_tx.tx_id)?;
    let expiry_renewed = client.contract_map(&contract, EXPIRY_BASE, &mike)?;
    let expect_expiry = until + years * YEAR_SECONDS;
    println!("\n[renew Mike.Q] {years} years, expiry {until} -> {expiry_renewed}");
    if expiry_renewed != expect_expiry {
        return Err(format!("renew did not extend expiry to {expect_expiry}, got {expiry_renewed}"));
    }
    let renewed_evt = find_event(&client, &contract, RENEWED_SELECTOR, renew_height)?.ok_or("no Renewed event")?;
    if word_at(&renewed_evt, 4)? != years {
        return Err("the Renewed event carried the wrong term after the full name".into());
    }
    fees_taken += RENEWAL_FEE * years;
    conservation(&client, &contract, fees_taken, swept, "after Mike.Q renew")?;

    // The core proof: A resolves Mike.Q to a full target address, and all four resolution words read
    // back reassemble to the whole thirty two byte target, no truncation.
    let target = b_id;
    let resolve_args = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(mike) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(target) },
        ],
    )?;
    let (resolve_tx, resolve_out) = client.call(&OWNER_A_SEED, 0, &contract, resolve_args, METER, fee)?;
    accepted(&resolve_out, "set_resolved")?;
    let resolve_height = poll_finality(&client, &resolve_tx.tx_id)?;
    let slots = client.storage(&contract)?;
    println!("\n[set_resolved Mike.Q] owner A resolves Mike.Q to a full target");
    let mut reassembled = [0u8; 32];
    for i in 0..4u64 {
        let key = addr_word_key(RESOLVED_BASE, &mike, i);
        let word = storage_value(&slots, &key);
        reassembled[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&word.to_be_bytes());
        println!("  resolution word {i}: slot {} = {:016x}", hex(&key), word);
    }
    if reassembled != target {
        return Err(format!(
            "the reassembled resolution {} does not equal the full target {}",
            hex(&reassembled),
            hex(&target)
        ));
    }
    let resolved_evt = find_event(&client, &contract, RESOLVED_SELECTOR, resolve_height)?.ok_or("no Resolved event")?;
    if addr_at(&resolved_evt, 64)? != target {
        return Err("the Resolved event did not carry the whole target address".into());
    }
    conservation(&client, &contract, fees_taken, swept, "after set_resolved")?;
    println!("[set_resolved Mike.Q] PROOF: all thirty two bytes of the target resolve back in full");

    println!("\n--- security ---");

    // Negative 1: B is a registered owner of Bob.Q, but does not own Mike.Q or Jeff.Q, so neither a
    // resolve of Mike.Q nor a transfer of Jeff.Q by B is accepted.
    let b_resolve = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(mike) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(stranger_id) },
        ],
    )?;
    let (br_tx, br_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve, METER, fee)?;
    accepted(&br_out, "B set_resolved of a name it does not own")?;
    let br_height = poll_finality(&client, &br_tx.tx_id)?;
    let mike_resolved = read_addr_value(&client, &contract, RESOLVED_BASE, &mike)?;
    if mike_resolved != target || find_event(&client, &contract, RESOLVED_SELECTOR, br_height)?.is_some() {
        return Err("a registered owner set_resolved a name it does not own".into());
    }
    println!("[neg1a] B could not set_resolved Mike.Q (owned by A): reverted, resolution unchanged, no event");

    let b_transfer = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(b_id) },
        ],
    )?;
    let (bt_tx, bt_out) = client.call(&OWNER_B_SEED, 0, &contract, b_transfer, METER, fee)?;
    accepted(&bt_out, "B transfer of a name it does not own")?;
    let bt_height = poll_finality(&client, &bt_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &jeff)? != a_id
        || find_event(&client, &contract, TRANSFERRED_SELECTOR, bt_height)?.is_some()
    {
        return Err("a registered owner transferred a name it does not own".into());
    }
    println!("[neg1b] B could not transfer Jeff.Q (owned by A): reverted, owner still A, no event");
    println!("[neg1 ] PROOF: per name ownership binds the full owner, a different registered owner is refused");
    conservation(&client, &contract, fees_taken, swept, "after B's refused attempts")?;

    // A transfers Jeff.Q to B, cleanly moving ownership.
    let transfer_args = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(b_id) },
        ],
    )?;
    let (transfer_tx, transfer_out) = client.call(&OWNER_A_SEED, 0, &contract, transfer_args, METER, fee)?;
    accepted(&transfer_out, "transfer")?;
    let transfer_height = poll_finality(&client, &transfer_tx.tx_id)?;
    assert_owner(&client, &contract, jeff, &b_id, "Jeff.Q owned by B in full")?;
    let transferred_evt = find_event(&client, &contract, TRANSFERRED_SELECTOR, transfer_height)?.ok_or("no Transferred event")?;
    if addr_at(&transferred_evt, 32)? != a_id || addr_at(&transferred_evt, 64)? != b_id {
        return Err("the Transferred event did not carry the whole prior and new owner".into());
    }
    println!("\n[transfer Jeff.Q] A -> B, owner_of[Jeff.Q] now reads B in full, event carries both owners");
    conservation(&client, &contract, fees_taken, swept, "after transfer")?;

    // Negative 2: the prior owner A can no longer act on Jeff.Q, the new owner B can.
    let a_resolve_jeff = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(a_id) },
        ],
    )?;
    let (arj_tx, arj_out) = client.call(&OWNER_A_SEED, 0, &contract, a_resolve_jeff, METER, fee)?;
    accepted(&arj_out, "prior owner set_resolved")?;
    let arj_height = poll_finality(&client, &arj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &jeff)? != [0u8; 32]
        || find_event(&client, &contract, RESOLVED_SELECTOR, arj_height)?.is_some()
    {
        return Err("the prior owner A set_resolved a transferred name".into());
    }
    println!("\n[neg2a] prior owner A could not set_resolved Jeff.Q after transfer: reverted, no event");

    let a_transfer_jeff = qcore::contract::build_call_args(
        TRANSFER_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TO_OFF, value: FieldValue::Address(a_id) },
        ],
    )?;
    let (atj_tx, atj_out) = client.call(&OWNER_A_SEED, 0, &contract, a_transfer_jeff, METER, fee)?;
    accepted(&atj_out, "prior owner transfer")?;
    let atj_height = poll_finality(&client, &atj_tx.tx_id)?;
    if read_addr_value(&client, &contract, OWNER_OF_BASE, &jeff)? != b_id
        || find_event(&client, &contract, TRANSFERRED_SELECTOR, atj_height)?.is_some()
    {
        return Err("the prior owner A transferred a name it no longer owns".into());
    }
    println!("[neg2b] prior owner A could not transfer Jeff.Q after transfer: reverted, owner still B, no event");

    let target2 = stranger_id;
    let b_resolve_jeff = qcore::contract::build_call_args(
        SET_RESOLVED_SELECTOR,
        &[
            FieldArg { offset: NAME_OFF, value: FieldValue::Address(jeff) },
            FieldArg { offset: TARGET_OFF, value: FieldValue::Address(target2) },
        ],
    )?;
    let (brj_tx, brj_out) = client.call(&OWNER_B_SEED, 0, &contract, b_resolve_jeff, METER, fee)?;
    accepted(&brj_out, "new owner set_resolved")?;
    let brj_height = poll_finality(&client, &brj_tx.tx_id)?;
    if read_addr_value(&client, &contract, RESOLVED_BASE, &jeff)? != target2 {
        return Err("the new owner B could not set_resolved Jeff.Q".into());
    }
    find_event(&client, &contract, RESOLVED_SELECTOR, brj_height)?.ok_or("no Resolved event for the new owner")?;
    println!("[neg2c] new owner B set_resolved Jeff.Q to a full target and it reassembles in full");
    println!("[neg2 ] PROOF: transfer moved the binding, the prior owner is gone and the new owner holds it");
    conservation(&client, &contract, fees_taken, swept, "after ownership move proofs")?;

    // Negative 3: an unexpired name cannot be re-registered, the trusted time after gate refuses it.
    let expiry_before = client.contract_map(&contract, EXPIRY_BASE, &jeff)?;
    let owner_before = read_addr_value(&client, &contract, OWNER_OF_BASE, &jeff)?;
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
    if client.contract_map(&contract, EXPIRY_BASE, &jeff)? != expiry_before
        || read_addr_value(&client, &contract, OWNER_OF_BASE, &jeff)? != owner_before
        || client.contract_scalar(&contract, VAULT_SLOT)? != vault_before_retake
        || find_event(&client, &contract, REGISTERED_SELECTOR, retake_height)?.is_some()
    {
        return Err("an unexpired name was re-registered, the after gate failed".into());
    }
    println!("\n[neg3 ] PROOF: an unexpired Jeff.Q could not be re-registered, expiry and owner unchanged, no fee, no event");
    conservation(&client, &contract, fees_taken, swept, "after refused retake")?;

    // Negative 4: a non admin cannot sweep, the signed by admin binding refuses the stranger's own order.
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
    if client.contract_scalar(&contract, VAULT_SLOT)? != vault_before_bad_sweep
        || find_event(&client, &contract, SWEPT_SELECTOR, bad_w_height)?.is_some()
    {
        return Err("a non admin swept the vault, the admin binding failed".into());
    }
    println!("\n[neg4 ] PROOF: a non admin sweep signed by {} was refused, vault unchanged, no event", hex(&bad_w_order.signer));
    conservation(&client, &contract, fees_taken, swept, "after refused withdraw")?;

    // The admin sweeps the whole vault to zero.
    let sweep = client.contract_scalar(&contract, VAULT_SLOT)?;
    let (w_tx, w_out, w_order) = client.call_typed_order(
        &OWNER_A_SEED,
        0,
        &contract,
        WITHDRAW_SELECTOR,
        WITHDRAW_SCHEME_OFF,
        WITHDRAW_PTR_OFF,
        REGION_OFF,
        &[FieldArg { offset: WITHDRAW_AMOUNT_OFF, value: FieldValue::Word(sweep) }],
        &OWNER_A_SEED,
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

/// The thirty two byte storage key of word `word` of an address valued map entry: SHA3 of the map's
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

fn assert_owner(client: &Client, contract: &str, name: [u8; 32], want: &[u8; 32], what: &str) -> Result<(), String> {
    let got = read_addr_value(client, contract, OWNER_OF_BASE, &name)?;
    if &got != want {
        return Err(format!("{what}: owner_of reads {} not {}", hex(&got), hex(want)));
    }
    println!("    [owner] {what}: {}", hex(&got));
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
