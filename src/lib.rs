// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod contract;
pub mod json;

#[cfg(feature = "client")]
mod http;

use json::{object, to_hex, Json};
use qtv_account::derive;
use qtv_codec::{to_bytes, Encoder};
use qtv_tx::{sign, Body, Call};
use qtv_wipe::Zeroizing;

pub use qtv_tx::{
    chain_id_from_name, LOCAL_CHAIN_ID, LOCAL_CHAIN_NAME, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME,
};

pub const TESTNET_CHAIN_NAME: &str = "Q-test-net-1";

pub const SEED_LEN: usize = 32;

pub const MAX_PLAUSIBLE_HEAD: u64 = 1 << 40;

#[cfg(feature = "client")]
const HEAD_BLOCKS_PER_SEC: u64 = 4;

#[cfg(feature = "client")]
const HEAD_SLACK_SECS: u64 = 60;

pub const ADDRESS_PAYLOAD_LEN: usize = 32;

pub const NATIVE_TRANSFER_METER: u64 = 1_210;

pub const MAX_METER_LIMIT: u64 = 12_500_000;

pub const MAX_CALL_ARGS: usize = 128 * 1024;

pub const MAX_VALIDITY_BLOCKS: u64 = 3_600;

pub const DENOMINATION: &str = "Quon";

pub const DECIMALS: u8 = 6;

#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub chain_id: Option<String>,
    pub rpc_url: Option<String>,
    pub explorer_url: Option<String>,
    pub denomination: String,
    pub decimals: u8,
    pub is_mainnet: bool,
}

impl Network {
    pub fn testnet() -> Network {
        Network {
            name: "testnet".to_string(),
            chain_id: Some(TESTNET_CHAIN_NAME.to_string()),
            rpc_url: None,
            explorer_url: Some("https://qvmscan.io".to_string()),
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: false,
        }
    }

    pub fn mainnet() -> Network {
        Network {
            name: "mainnet".to_string(),
            chain_id: Some("Q-main-net-1".to_string()),
            rpc_url: None,
            explorer_url: Some("https://qvmscan.io".to_string()),
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: true,
        }
    }

    pub fn for_url(base: impl Into<String>) -> Network {
        Network {
            name: "custom".to_string(),
            chain_id: None,
            rpc_url: Some(base.into()),
            explorer_url: None,
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: false,
        }
    }
}

pub fn testnet_chain_id() -> u64 {
    chain_id_from_name(TESTNET_CHAIN_NAME)
}

pub fn account_address(seed: &[u8; SEED_LEN], index: u64) -> String {
    derive(seed, index).address()
}

pub fn account_public_key(seed: &[u8; SEED_LEN], index: u64) -> Vec<u8> {
    derive(seed, index).public_key().to_vec()
}

pub fn key_register_address() -> String {
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/key/register"))
        .expect("a full hash reaches the address floor")
}

pub fn vm_deploy_address() -> String {
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/vm/deploy"))
        .expect("a full hash reaches the address floor")
}

pub fn contract_address(deployer: &str, nonce: u64) -> Option<String> {
    let payload = qtv_idfmt::parse_address(deployer).ok()?;
    if payload.len() != 32 {
        return None;
    }
    let mut input = Vec::with_capacity(16 + 32 + 8);
    input.extend_from_slice(b"qtv/vm/contract/");
    input.extend_from_slice(&payload);
    input.extend_from_slice(&nonce.to_le_bytes());
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(&input)).ok()
}

#[derive(Debug, Clone)]
pub struct SignedTransfer {
    pub from: String,
    pub tx_id: String,
    pub tx_bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_payable_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    value: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
) -> Result<SignedTransfer, String> {
    check_call(meter_limit, args.len(), fee, transfer_fee)?;
    sign_native(
        seed,
        index,
        target,
        args,
        value,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
        true,
    )
}

pub fn check_call(
    meter_limit: u64,
    args_len: usize,
    fee: u128,
    transfer_fee: u128,
) -> Result<(), String> {
    if !(NATIVE_TRANSFER_METER..=MAX_METER_LIMIT).contains(&meter_limit) {
        return Err(format!(
            "the meter limit {meter_limit} is outside the range {NATIVE_TRANSFER_METER} to {MAX_METER_LIMIT} the chain admits, refusing to sign"
        ));
    }
    if args_len > MAX_CALL_ARGS {
        return Err(format!(
            "the call arguments are {args_len} bytes, above the {MAX_CALL_ARGS} byte cap the chain admits, refusing to sign"
        ));
    }
    let required = vm_call_fee(transfer_fee, meter_limit);
    if fee < required {
        return Err(format!(
            "the fee {fee} is below the {required} a call metered at {meter_limit} pays at a transfer fee of {transfer_fee}, refusing to sign a call the chain would reject"
        ));
    }
    Ok(())
}

fn check_deadline(valid_until: u64) -> Result<(), String> {
    if valid_until == 0 {
        return Err(
            "a validity deadline of zero never expires, refusing to sign a transaction that stays valid forever"
                .to_string(),
        );
    }
    if valid_until > MAX_PLAUSIBLE_HEAD.saturating_add(MAX_VALIDITY_BLOCKS) {
        return Err(format!(
            "the validity deadline {valid_until} is past any height this chain can reach, refusing to sign a transaction that stays valid forever"
        ));
    }
    Ok(())
}

pub fn check_valid_until(valid_until: u64, head: u64) -> Result<(), String> {
    check_deadline(valid_until)?;
    if valid_until <= head {
        return Err(format!(
            "the validity deadline {valid_until} is not past the head {head}, refusing to sign a transaction that has already expired"
        ));
    }
    if valid_until - head > MAX_VALIDITY_BLOCKS {
        return Err(format!(
            "the validity deadline {valid_until} is more than {MAX_VALIDITY_BLOCKS} blocks past the head {head}, refusing to sign a transaction that stays valid that long"
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_native(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    value: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    calls_code: bool,
) -> Result<SignedTransfer, String> {
    if !valid_address(target) {
        return Err("the target is not a Q1 address".to_string());
    }
    check_deadline(valid_until)?;
    let sender = derive(seed, index);
    if !calls_code && address_payload(target)? == address_payload(&sender.address())? {
        return Err(
            "the recipient is the sending account itself and the chain refuses a self transfer, refusing to sign"
                .to_string(),
        );
    }
    let call = Call::new(target.to_string(), args);
    let body = Body::with_context(
        sender.address(),
        nonce,
        meter_limit,
        fee,
        call,
        value,
        chain_id,
    )
    .with_kind(if calls_code {
        qtv_tx::KIND_CALL
    } else {
        qtv_tx::KIND_TRANSFER
    })
    .valid_until(valid_until);
    let wrapper = sign(&sender, &body);
    Ok(SignedTransfer {
        from: sender.address(),
        tx_id: wrapper.id(),
        tx_bytes: to_bytes(&wrapper),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
) -> Result<SignedTransfer, String> {
    sign_payable_call(
        seed,
        index,
        target,
        args,
        0,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
        transfer_fee,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_asset_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    asset_issuer: &str,
    amount: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
) -> Result<SignedTransfer, String> {
    if !valid_address(target) {
        return Err("the target is not a Q1 address".to_string());
    }
    let issuer = qtv_idfmt::parse_address(asset_issuer)
        .map_err(|_| "the asset issuer is not a Q1 address".to_string())?;
    if issuer.len() != 32 {
        return Err("the asset issuer is not a Q1 address".to_string());
    }
    check_call(meter_limit, args.len(), fee, transfer_fee)?;
    check_deadline(valid_until)?;
    let mut issuer32 = [0u8; 32];
    issuer32.copy_from_slice(&issuer);
    let sender = derive(seed, index);
    let call = Call::new(target.to_string(), args);
    let body = Body::with_context(
        sender.address(),
        nonce,
        meter_limit,
        fee,
        call,
        amount,
        chain_id,
    )
    .calling()
    .carrying(issuer32)
    .valid_until(valid_until);
    let wrapper = sign(&sender, &body);
    Ok(SignedTransfer {
        from: sender.address(),
        tx_id: wrapper.id(),
        tx_bytes: to_bytes(&wrapper),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_transfer(
    seed: &[u8; SEED_LEN],
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
) -> Result<SignedTransfer, String> {
    if amount == 0 {
        return Err("a transfer of zero is refused, the chain rejects it".to_string());
    }
    let mut encoder = Encoder::new();
    encoder.put_u64(amount);
    sign_native(
        seed,
        index,
        to,
        encoder.into_bytes(),
        0,
        nonce,
        NATIVE_TRANSFER_METER,
        fee,
        chain_id,
        valid_until,
        false,
    )
}

pub fn sign_register(
    seed: &[u8; SEED_LEN],
    index: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
) -> Result<SignedTransfer, String> {
    let public_key = account_public_key(seed, index);
    sign_native(
        seed,
        index,
        &key_register_address(),
        public_key,
        0,
        nonce,
        NATIVE_TRANSFER_METER,
        fee,
        chain_id,
        valid_until,
        false,
    )
}

pub const DEFAULT_VALIDITY_BLOCKS: u64 = 300;

pub fn valid_until_from(info: &NodeInfo) -> u64 {
    info.head_height.saturating_add(DEFAULT_VALIDITY_BLOCKS)
}

pub fn vm_call_fee(transfer_fee: u128, meter_limit: u64) -> u128 {
    transfer_fee.saturating_mul(u128::from(
        meter_limit.div_ceil(NATIVE_TRANSFER_METER).max(1),
    ))
}

#[cfg(feature = "client")]
fn is_mainnet_chain(name: &str) -> bool {
    name.starts_with("Q-main-net-")
}

#[cfg(feature = "client")]
fn is_public_chain(name: &str) -> bool {
    name.starts_with("Q-test-net-") || is_mainnet_chain(name)
}

pub fn submit_body(tx_bytes: &[u8]) -> String {
    object(vec![("tx", Json::str(to_hex(tx_bytes)))]).render()
}

pub fn account_body(address: &str) -> String {
    object(vec![("address", Json::str(address))]).render()
}

pub fn transaction_body(tx_id: &str) -> String {
    object(vec![("tx_id", Json::str(tx_id))]).render()
}

pub fn block_by_height_body(height: u64) -> String {
    object(vec![("height", Json::Int(height))]).render()
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub chain_id: String,
    pub genesis_hash: String,
    pub head_height: u64,
    pub denomination: String,
    pub transfer_fee: u128,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub address: String,
    pub nonce: u64,
    pub balance: u128,
    pub scheme: u8,
    pub has_key: bool,
}

#[derive(Debug, Clone)]
pub enum Submit {
    Accepted {
        state: String,
        tx_id: String,
    },
    Rejected {
        reason: String,
        expected: Option<u64>,
        got: Option<u64>,
    },
}

#[derive(Debug, Clone)]
pub enum TxStatus {
    Finalised { height: u64, block: Option<String> },
    Pending,
    Unknown,
}

fn field_str(v: &Json, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Json::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("the response is missing a string {key}"))
}

fn field_u64(v: &Json, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("the response is missing a number {key}"))
}

fn field_u128(v: &Json, key: &str) -> Result<u128, String> {
    field_str(v, key)?
        .parse::<u128>()
        .map_err(|_| format!("the {key} field is not a number string"))
}

fn field_u8(v: &Json, key: &str) -> Result<u8, String> {
    let n = field_u64(v, key)?;
    u8::try_from(n).map_err(|_| format!("the {key} field is out of range for a byte"))
}

pub fn valid_address(address: &str) -> bool {
    matches!(qtv_idfmt::parse_address(address), Ok(payload) if payload.len() == ADDRESS_PAYLOAD_LEN)
}

pub const LOOKALIKE_EDGE: usize = 6;

pub fn same_address(a: &str, b: &str) -> bool {
    matches!((address_payload(a), address_payload(b)), (Ok(x), Ok(y)) if x == y)
}

fn shares_edges(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_uppercase(), b.to_ascii_uppercase());
    let head = |t: &str| t.get(2..2 + LOOKALIKE_EDGE).map(str::to_string);
    let tail = |t: &str| {
        t.len()
            .checked_sub(LOOKALIKE_EDGE)
            .and_then(|i| t.get(i..))
            .map(str::to_string)
    };
    head(&a).is_some() && head(&a) == head(&b) && tail(&a) == tail(&b)
}

pub fn lookalike_of(candidate: &str, known: &[String]) -> Option<String> {
    let target = address_payload(candidate).ok()?;
    known.iter().find_map(|other| {
        let payload = address_payload(other).ok()?;
        (payload != target && shares_edges(candidate, other)).then(|| other.clone())
    })
}

pub fn address_payload(address: &str) -> Result<[u8; 32], String> {
    let payload = qtv_idfmt::parse_address(address).map_err(|_| "not a Q1 address".to_string())?;
    payload
        .as_slice()
        .try_into()
        .map_err(|_| "the address is not the canonical thirty two byte width".to_string())
}

fn word_list() -> Vec<&'static str> {
    include_str!("english.txt").lines().collect()
}

pub fn mnemonic_from_seed(seed: &[u8; SEED_LEN]) -> Zeroizing<String> {
    let words = word_list();
    let checksum = qtv_crypto::sha3::sha3_256(seed)[0];
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SEED_LEN * 8 + 8));
    for &byte in seed.iter() {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    for shift in (0..8).rev() {
        bits.push((checksum >> shift) & 1);
    }
    let mut phrase = String::with_capacity(24 * 9);
    for chunk in bits.chunks(11) {
        let index = chunk
            .iter()
            .fold(0usize, |acc, &bit| (acc << 1) | bit as usize);
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(words[index]);
    }
    Zeroizing::new(phrase)
}

const STANDARD_PHRASE: &str = "this is a standard BIP-39 recovery phrase from another wallet, not a Quantova recovery phrase, so it cannot restore a Quantova account";

fn compat_letters(c: char) -> Option<String> {
    let code = u32::from(c);
    include_str!("nfkd.txt").lines().find_map(|line| {
        let mut parts = line.split(' ');
        let start = u32::from_str_radix(parts.next()?, 16).ok()?;
        let end = u32::from_str_radix(parts.next()?, 16).ok()?;
        let letters = parts.next()?;
        if !(start..=end).contains(&code) {
            return None;
        }
        if start == end {
            return Some(letters.to_string());
        }
        let first = *letters.as_bytes().first()?;
        let offset = u8::try_from(code - start).ok()?;
        Some(char::from(first.checked_add(offset)?).to_string())
    })
}

fn normalized_phrase(phrase: &str) -> Zeroizing<String> {
    let mut folded = Zeroizing::new(String::with_capacity(phrase.len().saturating_mul(2)));
    for c in phrase.chars() {
        if c.is_ascii() {
            folded.push(c.to_ascii_lowercase());
        } else if let Some(letters) = compat_letters(c) {
            folded.push_str(&letters);
        } else {
            folded.extend(c.to_lowercase());
        }
    }
    folded
}

fn bits_to_bytes(bits: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        bits.chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &bit| (acc << 1) | bit))
            .collect(),
    )
}

fn is_standard_phrase(bits: &[u8]) -> bool {
    if ![12, 15, 18, 21, 24].contains(&(bits.len() / 11)) {
        return false;
    }
    let checksum_bits = bits.len() / 33;
    let entropy_bits = bits.len() - checksum_bits;
    let digest = sha256(&bits_to_bytes(&bits[..entropy_bits]));
    (0..checksum_bits).all(|i| bits[entropy_bits + i] == (digest[i / 8] >> (7 - i % 8)) & 1)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = Zeroizing::new(Vec::with_capacity(data.len() + 72));
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());
    for block in message.chunks(64) {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.chunks(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for t in 16..64 {
            let low = schedule[t - 15];
            let high = schedule[t - 2];
            let s0 = low.rotate_right(7) ^ low.rotate_right(18) ^ (low >> 3);
            let s1 = high.rotate_right(17) ^ high.rotate_right(19) ^ (high >> 10);
            schedule[t] = schedule[t - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[t - 7])
                .wrapping_add(s1);
        }
        let mut work = state;
        for (k, w) in K.iter().zip(schedule.iter()) {
            let [a, b, c, d, e, f, g, h] = work;
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(*k)
                .wrapping_add(*w);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            work = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
        }
        for (slot, value) in state.iter_mut().zip(work) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 32];
    for (bytes, word) in out.chunks_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn seed_from_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; SEED_LEN]>, String> {
    let words = word_list();
    let folded = normalized_phrase(phrase);
    let entered: Vec<&str> = folded.split_whitespace().collect();
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(entered.len() * 11));
    for word in &entered {
        let index = words
            .iter()
            .position(|candidate| candidate == word)
            .ok_or("a word in the phrase is not in the word list")?;
        for shift in (0..11).rev() {
            bits.push(((index >> shift) & 1) as u8);
        }
    }
    if entered.len() != 24 {
        if is_standard_phrase(&bits) {
            return Err(STANDARD_PHRASE.to_string());
        }
        return Err("a recovery phrase is twenty four words".to_string());
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&bits_to_bytes(&bits[..SEED_LEN * 8]));
    let checksum = bits_to_bytes(&bits[SEED_LEN * 8..])[0];
    if checksum != qtv_crypto::sha3::sha3_256(&*seed)[0] {
        if is_standard_phrase(&bits) {
            return Err(STANDARD_PHRASE.to_string());
        }
        return Err("the recovery phrase checksum does not match, check for a typo".to_string());
    }
    Ok(seed)
}

pub fn parse_node_info(response: &str) -> Result<NodeInfo, String> {
    let v = json::parse(response)?;
    let fee = v.get("fee").ok_or("no fee in node info")?;
    Ok(NodeInfo {
        chain_id: field_str(&v, "chain_id")?,
        genesis_hash: field_str(&v, "genesis_hash")?,
        head_height: field_u64(&v, "head_height")?,
        denomination: field_str(&v, "denomination")?,
        transfer_fee: field_u128(fee, "transfer_quon")?,
        version: field_str(&v, "version")?,
    })
}

pub fn parse_account(response: &str) -> Result<Account, String> {
    let v = json::parse(response)?;
    Ok(Account {
        address: field_str(&v, "address")?,
        nonce: field_u64(&v, "nonce")?,
        balance: field_u128(&v, "balance")?,
        scheme: field_u8(&v, "scheme")?,
        has_key: v.get("has_key").and_then(Json::as_bool).unwrap_or(false),
    })
}

pub fn parse_submit(response: &str) -> Result<Submit, String> {
    let v = json::parse(response)?;
    match field_str(&v, "verdict")?.as_str() {
        "accepted" => Ok(Submit::Accepted {
            state: field_str(&v, "state")?,
            tx_id: field_str(&v, "tx_id")?,
        }),
        "rejected" => Ok(Submit::Rejected {
            reason: field_str(&v, "reason")?,
            expected: v.get("expected").and_then(Json::as_u64),
            got: v.get("got").and_then(Json::as_u64),
        }),
        other => Err(format!("unknown verdict {other}")),
    }
}

pub fn parse_transaction(response: &str) -> Result<TxStatus, String> {
    let v = json::parse(response)?;
    match field_str(&v, "status")?.as_str() {
        "finalised" => Ok(TxStatus::Finalised {
            height: field_u64(&v, "height")?,
            block: match v.get("block") {
                None | Some(Json::Null) => None,
                Some(block) => Some(
                    block
                        .as_str()
                        .ok_or("the block field is not a string")?
                        .to_string(),
                ),
            },
        }),
        "pending" => Ok(TxStatus::Pending),
        "unknown" => Ok(TxStatus::Unknown),
        other => Err(format!("unknown status {other}")),
    }
}

pub fn generate_seed() -> Result<Zeroizing<[u8; SEED_LEN]>, String> {
    #[cfg(unix)]
    {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        qtv_crypto::rng::try_fill_random(&mut *seed)
            .map_err(|_| "the operating system random source is unavailable".to_string())?;
        Ok(seed)
    }
    #[cfg(not(unix))]
    {
        Err(
            "generate_seed reads /dev/urandom and runs on unix only, so on another platform draw \
             thirty two bytes from the platform cryptographic random source and pass them in"
                .to_string(),
        )
    }
}

#[cfg(feature = "client")]
pub use client::Client;

#[cfg(feature = "client")]
mod client {
    use super::*;

    fn order_slot_key(contract: &str, signer: &[u8; 32]) -> String {
        let hex: String = signer.iter().map(|b| format!("{b:02x}")).collect();
        format!("{contract}/{hex}")
    }

    pub struct Client {
        base: String,
        network: Network,
        acknowledge_mainnet: bool,
        pinned_chain: std::cell::RefCell<Option<String>>,
        head_floor: std::cell::Cell<Option<(u64, std::time::Instant)>>,
        next_nonces: std::cell::RefCell<std::collections::HashMap<String, u64>>,
        signed_nonces: std::cell::RefCell<
            std::collections::HashMap<String, std::collections::BTreeMap<u64, u64>>,
        >,
    }

    fn fresh(base: String, network: Network, acknowledge_mainnet: bool) -> Client {
        Client {
            base: normalize_base(base),
            network,
            acknowledge_mainnet,
            pinned_chain: std::cell::RefCell::new(None),
            head_floor: std::cell::Cell::new(None),
            next_nonces: std::cell::RefCell::new(std::collections::HashMap::new()),
            signed_nonces: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    fn normalize_base(base: String) -> String {
        base.trim_end_matches('/').to_string()
    }

    impl Client {
        pub fn new(base: impl Into<String>) -> Client {
            let base = base.into();
            let network = Network::for_url(base.clone());
            fresh(base, network, false)
        }

        pub fn for_network(network: Network, acknowledge_mainnet: bool) -> Result<Client, String> {
            let base = network.rpc_url.clone().ok_or_else(|| {
                format!(
                    "the {} network has no rpc endpoint yet, pass the endpoint explicitly with Client::with_network",
                    network.name
                )
            })?;
            if network.is_mainnet && !acknowledge_mainnet {
                return Err("refusing to open a mainnet client without acknowledging it, a mainnet transaction moves real value so the network must be chosen on purpose".to_string());
            }
            Ok(fresh(base, network, acknowledge_mainnet))
        }

        pub fn with_network(
            base: impl Into<String>,
            network: Network,
            acknowledge_mainnet: bool,
        ) -> Client {
            fresh(base.into(), network, acknowledge_mainnet)
        }

        pub fn network(&self) -> &Network {
            &self.network
        }

        fn guard_mainnet(&self) -> Result<(), String> {
            if self.network.is_mainnet && !self.acknowledge_mainnet {
                let label = self.network.chain_id.clone().unwrap_or_default();
                return Err(format!(
                    "refusing to sign for the mainnet network {label} without acknowledging it, acknowledge mainnet when you mean to move real value"
                ));
            }
            Ok(())
        }

        pub(crate) fn signing_chain_id(&self, info: &NodeInfo) -> Result<u64, String> {
            let name = &info.chain_id;
            if name.is_empty() {
                return Err(
                    "the gateway did not report a chain id to bind the signature to".to_string(),
                );
            }
            let id = chain_id_from_name(name);
            let is_mainnet = is_mainnet_chain(name);
            if let Some(configured) = &self.network.chain_id {
                if name != configured {
                    return Err(format!(
                        "the gateway reports chain {name} but this client is configured for {configured}, refusing to sign a transaction that would be valid on a network you did not choose"
                    ));
                }
            } else {
                if is_public_chain(name) && !(is_mainnet && self.acknowledge_mainnet) {
                    return Err(format!(
                        "the gateway reports the public chain {name} but this client was opened for an unnamed network, configure the testnet or mainnet network before signing for it"
                    ));
                }
                let mut pinned = self.pinned_chain.borrow_mut();
                match pinned.as_ref() {
                    Some(first) if first != name => {
                        return Err(format!(
                            "the gateway reported {first} earlier in this session and now reports {name}, refusing to sign"
                        ));
                    }
                    Some(_) => {}
                    None => *pinned = Some(name.clone()),
                }
            }
            if is_mainnet && !self.acknowledge_mainnet {
                return Err(format!(
                    "the gateway reports the mainnet chain {name} but this client did not acknowledge mainnet, refusing to sign a mainnet transaction without acknowledging mainnet"
                ));
            }
            Ok(id)
        }

        fn rpc(&self, method: &str, body: String) -> Result<String, String> {
            let (status, text) = http::post(&self.base, &format!("/v1/{method}"), &body)?;
            if status == 200 {
                Ok(text)
            } else {
                Err(format!("the gateway returned {status}: {text}"))
            }
        }

        pub fn node_info(&self) -> Result<NodeInfo, String> {
            parse_node_info(&self.rpc("node_info", "{}".to_string())?)
        }

        pub fn account(&self, address: &str) -> Result<Account, String> {
            let account = parse_account(&self.rpc("get_account", account_body(address))?)?;
            if account.address != address {
                return Err(format!(
                    "the gateway answered for {} when asked about {address}, refusing to trust it",
                    account.address
                ));
            }
            Ok(account)
        }

        pub fn submit(&self, tx_bytes: &[u8]) -> Result<Submit, String> {
            parse_submit(&self.rpc("submit_transaction", submit_body(tx_bytes))?)
        }

        pub fn transaction(&self, tx_id: &str) -> Result<TxStatus, String> {
            parse_transaction(&self.rpc("get_transaction", transaction_body(tx_id))?)
        }

        pub fn transfer(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            to: &str,
            amount: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.transfer_expecting(seed, index, to, amount, max_fee, None)
        }

        pub fn transfer_expecting(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            to: &str,
            amount: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(to) {
                return Err("the recipient is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let sender = account_address(seed, index);
            let nonce = self.checked_nonce(&sender, expected_nonce, info.head_height)?;
            let signed = sign_transfer(
                seed,
                index,
                to,
                amount,
                nonce,
                info.transfer_fee,
                chain_id,
                valid_until,
            )?;
            self.remember_signed(&sender, nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&sender, nonce, &outcome);
            Ok((signed, outcome))
        }

        fn checked_nonce(
            &self,
            sender: &str,
            expected: Option<u64>,
            head: u64,
        ) -> Result<u64, String> {
            let account = self.account(sender)?;
            self.expected_slot(sender, account.nonce, expected, head)
        }

        fn expected_slot(
            &self,
            key: &str,
            reported: u64,
            expected: Option<u64>,
            head: u64,
        ) -> Result<u64, String> {
            if let Some(exp) = expected {
                if exp != reported {
                    return Err(format!(
                        "the gateway reported nonce {reported} but you expected {exp}; the chain admits \
                         only the nonce the account has reached, refusing to sign"
                    ));
                }
            }
            {
                let mut next = self.next_nonces.borrow_mut();
                let local = next.entry(key.to_string()).or_insert(reported);
                *local = (*local).max(reported);
            }
            if let Some(held) = self.signed_nonces.borrow_mut().get_mut(key) {
                held.retain(|_, until| *until >= head);
                if expected.is_none() && held.contains_key(&reported) {
                    return Err(format!(
                        "a transaction was already signed for nonce {reported} in this session and was \
                         neither rejected nor expired; if it was never broadcast, pass that nonce \
                         explicitly to sign at it again"
                    ));
                }
            }
            Ok(reported)
        }

        fn remember_signed(&self, key: &str, used: u64, valid_until: u64) {
            self.signed_nonces
                .borrow_mut()
                .entry(key.to_string())
                .or_default()
                .insert(used, valid_until);
        }

        fn remember_used(&self, key: &str, used: u64, outcome: &Submit) {
            match outcome {
                Submit::Accepted { .. } => {
                    let mut next = self.next_nonces.borrow_mut();
                    let local = next.entry(key.to_string()).or_insert(0);
                    *local = (*local).max(used.saturating_add(1));
                }
                Submit::Rejected { .. } => {
                    if let Some(held) = self.signed_nonces.borrow_mut().get_mut(key) {
                        held.remove(&used);
                    }
                }
            }
        }

        fn validity(&self, info: &NodeInfo) -> Result<u64, String> {
            let head = info.head_height;
            if head > MAX_PLAUSIBLE_HEAD {
                return Err(format!(
                    "the gateway reports head {head}, past any height this chain can have reached, refusing to sign"
                ));
            }
            let now = std::time::Instant::now();
            if let Some((floor, at)) = self.head_floor.get() {
                if head < floor {
                    return Err(format!(
                        "the gateway reports head {head} below the {floor} it reported earlier, refusing to sign"
                    ));
                }
                let allowed = now
                    .duration_since(at)
                    .as_secs()
                    .saturating_add(HEAD_SLACK_SECS)
                    .saturating_mul(HEAD_BLOCKS_PER_SEC);
                if head > floor.saturating_add(allowed) {
                    return Err(format!(
                        "the gateway head leapt from {floor} to {head} faster than blocks are made, refusing to sign"
                    ));
                }
            }
            let valid_until = valid_until_from(info);
            check_valid_until(valid_until, head)?;
            if self.head_floor.get().is_none_or(|(floor, _)| head > floor) {
                self.head_floor.set(Some((head, now)));
            }
            Ok(valid_until)
        }

        fn fee_within(&self, fee: u128, max_fee: u128) -> Result<u128, String> {
            if fee > max_fee {
                return Err(format!(
                    "the fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
                ));
            }
            Ok(fee)
        }

        pub fn call(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.call_payable_expecting(seed, index, target, args, 0, meter_limit, max_fee, None)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_payable(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            value: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.call_payable_expecting(
                seed,
                index,
                target,
                args,
                value,
                meter_limit,
                max_fee,
                None,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_payable_expecting(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            value: u64,
            meter_limit: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(target) {
                return Err("the target is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let sender = account_address(seed, index);
            let nonce = self.checked_nonce(&sender, expected_nonce, info.head_height)?;
            let signed = sign_payable_call(
                seed,
                index,
                target,
                args,
                value,
                nonce,
                meter_limit,
                fee,
                chain_id,
                valid_until,
                info.transfer_fee,
            )?;
            self.remember_signed(&sender, nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&sender, nonce, &outcome);
            Ok((signed, outcome))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_asset(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            asset_issuer: &str,
            amount: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.call_asset_expecting(
                seed,
                index,
                target,
                args,
                asset_issuer,
                amount,
                meter_limit,
                max_fee,
                None,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_asset_expecting(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            asset_issuer: &str,
            amount: u64,
            meter_limit: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let sender = account_address(seed, index);
            let nonce = self.checked_nonce(&sender, expected_nonce, info.head_height)?;
            let signed = sign_asset_call(
                seed,
                index,
                target,
                args,
                asset_issuer,
                amount,
                nonce,
                meter_limit,
                fee,
                chain_id,
                valid_until,
                info.transfer_fee,
            )?;
            self.remember_signed(&sender, nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&sender, nonce, &outcome);
            Ok((signed, outcome))
        }

        pub fn storage(&self, contract: &str) -> Result<Vec<contract::StorageSlot>, String> {
            contract::parse_storage(&self.rpc("get_storage", contract::storage_body(contract))?)
        }

        pub fn events(&self, height: u64) -> Result<Vec<contract::ContractEvent>, String> {
            contract::parse_events(&self.rpc("get_events", contract::events_body(height))?)
        }

        pub fn asset_balance(&self, issuer: &str, holder: &str) -> Result<u128, String> {
            if !valid_address(issuer) || !valid_address(holder) {
                return Err("the issuer or holder is not a Q1 address".to_string());
            }
            let response = self.rpc(
                "get_asset_balance",
                contract::asset_balance_body(issuer, holder),
            )?;
            field_u128(&json::parse(&response)?, "balance")
        }

        pub fn storage_at(
            &self,
            contract: &str,
            keys: &[[u8; 32]],
        ) -> Result<Vec<contract::StorageSlot>, String> {
            contract::parse_storage(
                &self.rpc("get_storage_at", contract::storage_at_body(contract, keys))?,
            )
        }

        fn slot_value(&self, contract: &str, key: &[u8; 32]) -> Result<u64, String> {
            Ok(crate::contract::storage_value(
                &self.storage_at(contract, std::slice::from_ref(key))?,
                key,
            ))
        }

        pub fn contract_nonce(&self, contract: &str, signer: &[u8; 32]) -> Result<u64, String> {
            self.slot_value(contract, &crate::contract::nonce_slot_key(signer))
        }

        pub fn contract_scalar(&self, contract: &str, slot: u64) -> Result<u64, String> {
            self.slot_value(contract, &crate::contract::scalar_slot_key(slot))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_signed_order(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            layout: &contract::OrderLayout,
            fields: &[u64],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            self.call_signed_order_expecting(
                caller_seed,
                caller_index,
                contract,
                selector,
                layout,
                fields,
                owner_seed,
                owner_index,
                meter_limit,
                max_fee,
                None,
                None,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_signed_order_expecting(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            layout: &contract::OrderLayout,
            fields: &[u64],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            meter_limit: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
            expected_order_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            if !valid_address(contract) {
                return Err("the contract is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let order_key = order_slot_key(contract, &signer);
            let nonce = self.expected_slot(
                &order_key,
                self.contract_nonce(contract, &signer)?,
                expected_order_nonce,
                info.head_height,
            )?;
            let order = contract::build_signed_order_call(
                chain_id,
                contract,
                selector,
                layout,
                fields,
                owner_seed,
                owner_index,
                nonce,
            )?;
            let caller = account_address(caller_seed, caller_index);
            let account_nonce = self.checked_nonce(&caller, expected_nonce, info.head_height)?;
            let signed = sign_call(
                caller_seed,
                caller_index,
                contract,
                order.call_args.clone(),
                account_nonce,
                meter_limit,
                fee,
                chain_id,
                valid_until,
                info.transfer_fee,
            )?;
            self.remember_signed(&caller, account_nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&caller, account_nonce, &outcome);
            self.remember_used(&order_key, nonce, &outcome);
            Ok((signed, outcome, order))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_typed_order(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            scheme_off: u64,
            ptr_off: u64,
            region_off: u64,
            fields: &[contract::FieldArg],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            value: u64,
            in_asset: Option<&str>,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            self.call_typed_order_expecting(
                caller_seed,
                caller_index,
                contract,
                selector,
                scheme_off,
                ptr_off,
                region_off,
                fields,
                owner_seed,
                owner_index,
                value,
                in_asset,
                meter_limit,
                max_fee,
                None,
                None,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_typed_order_expecting(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            scheme_off: u64,
            ptr_off: u64,
            region_off: u64,
            fields: &[contract::FieldArg],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            value: u64,
            in_asset: Option<&str>,
            meter_limit: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
            expected_order_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            if !valid_address(contract) {
                return Err("the contract is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let order_key = order_slot_key(contract, &signer);
            let nonce = self.expected_slot(
                &order_key,
                self.contract_nonce(contract, &signer)?,
                expected_order_nonce,
                info.head_height,
            )?;
            let order = contract::build_typed_order_call(
                chain_id,
                contract,
                selector,
                scheme_off,
                ptr_off,
                region_off,
                fields,
                owner_seed,
                owner_index,
                nonce,
            )?;
            let caller = account_address(caller_seed, caller_index);
            let account_nonce = self.checked_nonce(&caller, expected_nonce, info.head_height)?;
            let args = order.call_args.clone();
            let signed = match in_asset {
                Some(issuer) => sign_asset_call(
                    caller_seed,
                    caller_index,
                    contract,
                    args,
                    issuer,
                    value,
                    account_nonce,
                    meter_limit,
                    fee,
                    chain_id,
                    valid_until,
                    info.transfer_fee,
                )?,
                None => sign_payable_call(
                    caller_seed,
                    caller_index,
                    contract,
                    args,
                    value,
                    account_nonce,
                    meter_limit,
                    fee,
                    chain_id,
                    valid_until,
                    info.transfer_fee,
                )?,
            };
            self.remember_signed(&caller, account_nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&caller, account_nonce, &outcome);
            self.remember_used(&order_key, nonce, &outcome);
            Ok((signed, outcome, order))
        }

        pub fn deploy_with_params(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            container: &[u8],
            params: &[contract::DeployParam],
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, String), String> {
            self.deploy_with_params_expecting(
                seed,
                index,
                container,
                params,
                meter_limit,
                max_fee,
                None,
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn deploy_with_params_expecting(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            container: &[u8],
            params: &[contract::DeployParam],
            meter_limit: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit, String), String> {
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let deployer = account_address(seed, index);
            let account_nonce = self.checked_nonce(&deployer, expected_nonce, info.head_height)?;
            let args = contract::build_deploy_call(container, params);
            let contract = contract_address(&deployer, account_nonce)
                .ok_or("the deployer is not a Q1 address")?;
            let signed = sign_call(
                seed,
                index,
                &vm_deploy_address(),
                args,
                account_nonce,
                meter_limit,
                fee,
                chain_id,
                valid_until,
                info.transfer_fee,
            )?;
            self.remember_signed(&deployer, account_nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&deployer, account_nonce, &outcome);
            Ok((signed, outcome, contract))
        }

        pub fn contract_map(
            &self,
            contract: &str,
            map_domain_tag: u64,
            key: &[u8; 32],
        ) -> Result<u64, String> {
            self.slot_value(
                contract,
                &crate::contract::map_slot_key(map_domain_tag, key),
            )
        }

        pub fn register(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.register_expecting(seed, index, max_fee, None)
        }

        pub fn register_expecting(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            max_fee: u128,
            expected_nonce: Option<u64>,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let sender = account_address(seed, index);
            let nonce = self.checked_nonce(&sender, expected_nonce, info.head_height)?;
            let signed =
                sign_register(seed, index, nonce, info.transfer_fee, chain_id, valid_until)?;
            self.remember_signed(&sender, nonce, valid_until);
            let outcome = self.submit(&signed.tx_bytes)?;
            self.remember_used(&sender, nonce, &outcome);
            Ok((signed, outcome))
        }
    }

    #[cfg(test)]
    mod session_tests {
        use super::*;

        #[test]
        fn an_order_nonce_is_read_by_its_own_key() {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let signer = [9u8; 32];
            let key = json::to_hex(&crate::contract::nonce_slot_key(&signer));
            let expected = key.clone();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&raw).to_string();
                let body = format!(
                    "{{\"address\":\"x\",\"slots\":[{{\"slot\":\"{expected}\",\"value\":\"7\"}}]}}"
                );
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
                request
            });
            let contract = contract_address(&account_address(&[1u8; 32], 0), 0).unwrap();
            let nonce = Client::new(base)
                .contract_nonce(&contract, &signer)
                .unwrap();
            let request = server.join().unwrap();
            assert_eq!(nonce, 7);
            assert!(request.starts_with("POST /v1/get_storage_at "));
            assert!(request.contains(&key));
        }

        fn info(chain: &str, head: u64) -> NodeInfo {
            NodeInfo {
                chain_id: chain.to_string(),
                genesis_hash: String::new(),
                head_height: head,
                denomination: DENOMINATION.to_string(),
                transfer_fee: 500,
                version: String::new(),
            }
        }

        #[test]
        fn an_unnamed_client_refuses_a_public_chain_and_pins_the_first_private_one() {
            let client = Client::new("http://127.0.0.1:1");
            assert!(client.signing_chain_id(&info("Q-test-net-1", 1)).is_err());
            assert!(client.signing_chain_id(&info("Q-main-net-1", 1)).is_err());
            assert!(client.signing_chain_id(&info("Q-dev-net-7", 1)).is_ok());
            assert!(client.signing_chain_id(&info("Q-dev-net-8", 1)).is_err());
        }

        #[test]
        fn a_head_past_the_plausible_range_or_leaping_is_refused() {
            let client = Client::new("http://127.0.0.1:1");
            assert!(client.validity(&info("Q-dev-net-7", u64::MAX)).is_err());
            assert_eq!(
                client.validity(&info("Q-dev-net-7", 1_000)).unwrap(),
                1_000 + DEFAULT_VALIDITY_BLOCKS
            );
            assert!(client.validity(&info("Q-dev-net-7", 999)).is_err());
            assert!(client
                .validity(&info("Q-dev-net-7", 1_000 + 10_000))
                .is_err());
            assert!(client.validity(&info("Q-dev-net-7", 1_010)).is_ok());
        }

        #[test]
        fn the_head_floor_rises_to_the_highest_head_seen() {
            let client = Client::new("http://127.0.0.1:1");
            assert!(client.validity(&info("Q-dev-net-7", 1_000)).is_ok());
            assert!(client.validity(&info("Q-dev-net-7", 1_200)).is_ok());
            assert_eq!(client.head_floor.get().map(|(floor, _)| floor), Some(1_200));
            assert!(
                client.validity(&info("Q-dev-net-7", 1_100)).is_err(),
                "a head below the highest one seen is refused, not only one below the first"
            );
            assert!(client.validity(&info("Q-dev-net-7", 1_200)).is_ok());
            assert_eq!(client.head_floor.get().map(|(floor, _)| floor), Some(1_200));
        }

        #[test]
        fn a_validity_deadline_is_capped_past_the_head() {
            assert!(check_valid_until(1_000 + DEFAULT_VALIDITY_BLOCKS, 1_000).is_ok());
            assert!(check_valid_until(1_000 + MAX_VALIDITY_BLOCKS, 1_000).is_ok());
            assert!(check_valid_until(1_000 + MAX_VALIDITY_BLOCKS + 1, 1_000).is_err());
            assert!(check_valid_until(1_000, 1_000).is_err());
            assert!(check_valid_until(0, 0).is_err());
            assert_eq!(MAX_VALIDITY_BLOCKS, 3_600);
        }

        fn accepted() -> Submit {
            Submit::Accepted {
                state: String::new(),
                tx_id: String::new(),
            }
        }

        fn rejected() -> Submit {
            Submit::Rejected {
                reason: String::new(),
                expected: None,
                got: None,
            }
        }

        #[test]
        fn an_expected_nonce_must_be_the_reported_one() {
            let client = Client::new("http://127.0.0.1:1");
            assert!(client.expected_slot("b", 9, Some(3), 10).is_err());
            assert!(
                client.expected_slot("b", 2, Some(3), 10).is_err(),
                "the mempool admits only the nonce the account has reached, so a slot ahead of it is refused"
            );
            assert_eq!(client.expected_slot("b", 3, Some(3), 10).unwrap(), 3);
        }

        #[test]
        fn the_local_nonce_follows_the_highest_reported_one_rather_than_refusing() {
            let client = Client::new("http://127.0.0.1:1");
            assert_eq!(client.expected_slot("a", 4, None, 10).unwrap(), 4);
            client.remember_used("a", 4, &accepted());
            assert_eq!(client.next_nonces.borrow().get("a").copied(), Some(5));
            assert_eq!(
                client.expected_slot("a", 9, None, 10).unwrap(),
                9,
                "a gateway ahead of the local nonce raises it"
            );
            assert_eq!(client.next_nonces.borrow().get("a").copied(), Some(9));
            assert_eq!(
                client.expected_slot("a", 4, None, 10).unwrap(),
                4,
                "a submission that never lands leaves the chain at 4, and 4 is what it will admit"
            );
            assert_eq!(client.next_nonces.borrow().get("a").copied(), Some(9));
        }

        #[test]
        fn a_signed_nonce_is_held_until_it_is_rejected_or_expires() {
            let client = Client::new("http://127.0.0.1:1");
            client.remember_signed("a", 4, 310);
            assert!(
                client.expected_slot("a", 4, None, 10).is_err(),
                "a slot already signed this session is not signed again unnamed"
            );
            assert_eq!(
                client.expected_slot("a", 4, Some(4), 10).unwrap(),
                4,
                "naming the slot is how a caller says the first never landed"
            );
            client.remember_used("a", 4, &rejected());
            assert_eq!(
                client.expected_slot("a", 4, None, 10).unwrap(),
                4,
                "a rejected submission frees its slot"
            );
            client.remember_signed("a", 4, 310);
            assert!(
                client.expected_slot("a", 4, None, 310).is_err(),
                "a transaction is still live at its deadline height"
            );
            assert_eq!(
                client.expected_slot("a", 4, None, 311).unwrap(),
                4,
                "a deadline that has passed frees its slot"
            );
        }

        fn gateway(replies: Vec<String>) -> String {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                for body in replies {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut buf).unwrap();
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw);
                        if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                            let len: usize = head
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length: "))
                                .unwrap()
                                .trim()
                                .parse()
                                .unwrap();
                            if rest.len() >= len {
                                break;
                            }
                        }
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(reply.as_bytes()).unwrap();
                }
            });
            base
        }

        fn node_info_reply(chain: &str, head: u64) -> String {
            format!(
                "{{\"chain_id\":\"{chain}\",\"genesis_hash\":\"g\",\"head_height\":{head},\
                 \"denomination\":\"Quon\",\"fee\":{{\"transfer_quon\":\"500\"}},\"version\":\"t\"}}"
            )
        }

        #[test]
        fn a_refused_signing_leaves_no_nonce_held() {
            let seed = [3u8; 32];
            let sender = account_address(&seed, 0);
            let account = format!(
                "{{\"address\":\"{sender}\",\"nonce\":0,\"balance\":\"0\",\"scheme\":1,\"has_key\":true}}"
            );
            let base = gateway(vec![
                node_info_reply("Q-dev-net-1", 10),
                node_info_reply("Q-dev-net-1", MAX_PLAUSIBLE_HEAD + 1),
                node_info_reply("Q-dev-net-1", 10),
                account,
            ]);
            let to = account_address(&seed, 1);
            let configured = Client::with_network(base.clone(), Network::testnet(), false);
            assert!(configured.transfer(&seed, 0, &to, 5, 500).is_err());
            assert!(configured.signed_nonces.borrow().is_empty());
            let client = Client::new(base);
            assert!(client.transfer(&seed, 0, &to, 5, 500).is_err());
            assert!(client
                .transfer(&seed, 0, &sender, 5, 500)
                .unwrap_err()
                .contains("self transfer"));
            assert!(
                client.signed_nonces.borrow().is_empty(),
                "a chain, head or signing refusal must not hold the nonce it never signed"
            );
            assert_eq!(client.next_nonces.borrow().get(&sender).copied(), Some(0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contract_call_pays_one_transfer_fee_per_transfer_meter() {
        assert_eq!(vm_call_fee(500, 1), 500);
        assert_eq!(vm_call_fee(500, NATIVE_TRANSFER_METER), 500);
        assert_eq!(vm_call_fee(500, NATIVE_TRANSFER_METER + 1), 1_000);
        assert_eq!(vm_call_fee(500, 12_000_000), 500 * 9_918);
    }

    #[test]
    fn a_call_is_refused_outside_the_chain_meter_range_args_cap_or_fee_floor() {
        let seed = [7u8; SEED_LEN];
        let target = account_address(&seed, 1);
        let call = |args: Vec<u8>, meter: u64, fee: u128| {
            sign_call(
                &seed,
                0,
                &target,
                args,
                0,
                meter,
                fee,
                LOCAL_CHAIN_ID,
                300,
                500,
            )
        };
        assert_eq!(NATIVE_TRANSFER_METER, 1_210);
        assert_eq!(MAX_METER_LIMIT, 50_000_000 / 4);
        assert_eq!(MAX_CALL_ARGS, 131_072);
        assert!(call(vec![1], NATIVE_TRANSFER_METER - 1, 500).is_err());
        assert!(call(vec![1], NATIVE_TRANSFER_METER, 500).is_ok());
        assert!(call(vec![1], MAX_METER_LIMIT, vm_call_fee(500, MAX_METER_LIMIT)).is_ok());
        assert!(call(
            vec![1],
            MAX_METER_LIMIT + 1,
            vm_call_fee(500, MAX_METER_LIMIT + 1)
        )
        .is_err());
        assert!(call(vec![0; MAX_CALL_ARGS], 21_000, vm_call_fee(500, 21_000)).is_ok());
        assert!(call(vec![0; MAX_CALL_ARGS + 1], 21_000, vm_call_fee(500, 21_000)).is_err());
        let underpriced = call(vec![1], 21_000, 500).unwrap_err();
        assert!(underpriced.contains("below"), "{underpriced}");
        assert!(call(vec![1], 21_000, vm_call_fee(500, 21_000) - 1).is_err());
        assert!(call(vec![1], 21_000, vm_call_fee(500, 21_000)).is_ok());
        assert!(sign_asset_call(
            &seed,
            0,
            &target,
            vec![1],
            &target,
            5,
            0,
            21_000,
            500,
            LOCAL_CHAIN_ID,
            300,
            500
        )
        .is_err());
        assert!(sign_payable_call(
            &seed,
            0,
            &target,
            vec![1],
            5,
            0,
            5_000_000,
            500,
            LOCAL_CHAIN_ID,
            300,
            500
        )
        .is_err());
    }

    #[test]
    fn a_self_transfer_or_a_deadline_that_never_expires_is_refused() {
        let seed = [7u8; SEED_LEN];
        let own = account_address(&seed, 0);
        let other = account_address(&seed, 1);
        let refused = sign_transfer(&seed, 0, &own, 1000, 0, 500, LOCAL_CHAIN_ID, 300).unwrap_err();
        assert!(refused.contains("self transfer"), "{refused}");
        assert!(sign_transfer(
            &seed,
            0,
            &own.to_ascii_lowercase(),
            1000,
            0,
            500,
            LOCAL_CHAIN_ID,
            300
        )
        .is_err());
        assert!(sign_transfer(&seed, 0, &other, 1000, 0, 500, LOCAL_CHAIN_ID, 300).is_ok());
        let forever = sign_transfer(&seed, 0, &other, 1000, 0, 500, LOCAL_CHAIN_ID, 0).unwrap_err();
        assert!(forever.contains("never expires"), "{forever}");
        assert!(sign_register(&seed, 0, 0, 500, LOCAL_CHAIN_ID, 0).is_err());
        assert!(sign_call(
            &seed,
            0,
            &other,
            vec![1],
            0,
            1210,
            500,
            LOCAL_CHAIN_ID,
            0,
            500
        )
        .is_err());
        assert!(sign_asset_call(
            &seed,
            0,
            &other,
            vec![1],
            &other,
            5,
            0,
            1210,
            500,
            LOCAL_CHAIN_ID,
            0,
            500
        )
        .is_err());
        assert!(sign_transfer(&seed, 0, &other, 1000, 0, 500, LOCAL_CHAIN_ID, u64::MAX).is_err());
    }

    #[test]
    fn lookalike_edges_compare_the_first_and_last_six_characters() {
        let a = "Q1ABCDEF0000000000000000000000000000000000000000000000UVWXYZ";
        assert!(shares_edges(
            a,
            "Q1ABCDEF1111111111111111111111111111111111111111111111UVWXYZ"
        ));
        assert!(shares_edges(a, &a.to_ascii_lowercase()));
        assert!(!shares_edges(
            a,
            "Q1ABCDEX0000000000000000000000000000000000000000000000UVWXYZ"
        ));
        assert!(!shares_edges(
            a,
            "Q1ABCDEF0000000000000000000000000000000000000000000000UVWXYQ"
        ));
        assert!(!shares_edges("Q1", "Q1"));
    }

    #[test]
    fn the_testnet_chain_id_follows_the_testnet_network() {
        let configured = Network::testnet().chain_id.unwrap();
        assert_eq!(configured, "Q-test-net-1");
        assert_eq!(testnet_chain_id(), chain_id_from_name(&configured));
        assert_eq!(testnet_chain_id(), qtv_tx::TESTNET_CHAIN_ID);
    }

    #[test]
    fn a_finalised_transaction_from_a_pruned_block_has_no_block() {
        match parse_transaction("{\"tx_id\":\"t\",\"status\":\"finalised\",\"height\":7}").unwrap()
        {
            TxStatus::Finalised { height, block } => {
                assert_eq!(height, 7);
                assert!(block.is_none());
            }
            other => panic!("expected a finalised status, got {other:?}"),
        }
        match parse_transaction(
            "{\"tx_id\":\"t\",\"status\":\"finalised\",\"height\":7,\"block\":\"QBLK1\"}",
        )
        .unwrap()
        {
            TxStatus::Finalised { block, .. } => assert_eq!(block.as_deref(), Some("QBLK1")),
            other => panic!("expected a finalised status, got {other:?}"),
        }
        assert!(parse_transaction(
            "{\"tx_id\":\"t\",\"status\":\"finalised\",\"height\":7,\"block\":7}"
        )
        .is_err());
    }

    #[test]
    fn sha256_matches_the_published_vectors() {
        assert_eq!(
            json::to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            json::to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            json::to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn a_phrase_is_normalised_before_it_is_looked_up() {
        let seed = [7u8; SEED_LEN];
        let phrase = mnemonic_from_seed(&seed);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let messy = format!(
            "  \t{}\u{00a0}\u{3000}{}  \n",
            words[..12].join("   ").to_uppercase(),
            words[12..].join(" \u{2003} ")
        );
        assert_eq!(*seed_from_mnemonic(&messy).unwrap(), seed);
        let wide: String = phrase
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    char::from_u32(u32::from(c) - u32::from('a') + 0xff41).unwrap()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(*seed_from_mnemonic(&wide).unwrap(), seed);
        let bold: String = phrase
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    char::from_u32(u32::from(c) - u32::from('a') + 0x1d400).unwrap()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(*seed_from_mnemonic(&bold).unwrap(), seed);
        let ligatured = phrase.replace("fi", "\u{fb01}").replace("fl", "\u{fb02}");
        assert_eq!(*seed_from_mnemonic(&ligatured).unwrap(), seed);
        assert!(seed_from_mnemonic(&phrase.replacen('a', "\u{e1}", 1)).is_err());
    }

    #[test]
    fn a_standard_bip39_phrase_is_named_as_one() {
        let zero_24 = format!("{} art", ["abandon"; 23].join(" "));
        let zero_12 = format!("{} about", ["abandon"; 11].join(" "));
        let vector_12 =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let vector_24 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        for phrase in [zero_24.as_str(), zero_12.as_str(), vector_12, vector_24] {
            let err = seed_from_mnemonic(phrase).unwrap_err();
            assert_eq!(err, STANDARD_PHRASE, "{phrase}");
        }
        let typo = format!("{} abandon", ["abandon"; 23].join(" "));
        assert!(seed_from_mnemonic(&typo)
            .unwrap_err()
            .contains("check for a typo"));
        let short = ["abandon"; 12].join(" ");
        assert!(seed_from_mnemonic(&short)
            .unwrap_err()
            .contains("twenty four words"));
        for byte in 0u8..=255 {
            let seed = [byte; SEED_LEN];
            assert_eq!(
                *seed_from_mnemonic(&mnemonic_from_seed(&seed)).unwrap(),
                seed,
                "a Quantova phrase derives what it did before, even where its checksum also passes as a standard phrase"
            );
        }
    }

    #[test]
    fn a_transfer_and_a_call_are_distinct_transactions() {
        let seed = [7u8; SEED_LEN];
        let to = account_address(&seed, 1);
        let transfer = sign_transfer(&seed, 0, &to, 1000, 3, 500, LOCAL_CHAIN_ID, 300).unwrap();
        let mut encoder = Encoder::new();
        encoder.put_u64(1000);
        let call = sign_call(
            &seed,
            0,
            &to,
            encoder.into_bytes(),
            3,
            NATIVE_TRANSFER_METER,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        assert_ne!(
            transfer.tx_bytes, call.tx_bytes,
            "a transfer and a call carrying the same bytes must not be the same \
             transaction; when they were, a call to an address that did not hold \
             code yet executed as a transfer of its own arguments"
        );
        assert_ne!(transfer.tx_id, call.tx_id);
    }

    #[test]
    fn a_derived_address_renders_uppercase_q1() {
        let address = account_address(&[7u8; SEED_LEN], 0);
        assert!(address.starts_with("Q1"));
        assert_eq!(address, address.to_ascii_uppercase());
    }

    #[test]
    fn a_payable_call_binds_the_value_into_the_signature() {
        let seed = [7u8; SEED_LEN];
        let target = account_address(&seed, 1);
        let free = sign_call(
            &seed,
            0,
            &target,
            vec![1, 2, 3],
            5,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        let payable_zero = sign_payable_call(
            &seed,
            0,
            &target,
            vec![1, 2, 3],
            0,
            5,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        assert_eq!(free.tx_bytes, payable_zero.tx_bytes);
        assert_eq!(free.tx_id, payable_zero.tx_id);
        let funded = sign_payable_call(
            &seed,
            0,
            &target,
            vec![1, 2, 3],
            1000,
            5,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        assert_ne!(funded.tx_bytes, free.tx_bytes);
        assert_ne!(funded.tx_id, free.tx_id);
    }

    #[test]
    fn the_signed_bytes_match_the_chain_body_and_verify() {
        let seed = [7u8; SEED_LEN];
        let sender = derive(&seed, 0);
        let target = account_address(&seed, 1);
        let call = Call::new(target.clone(), vec![9, 9, 9]);
        let body = Body::with_context(sender.address(), 4, 1210, 750, call, 2500, LOCAL_CHAIN_ID)
            .calling()
            .valid_until(300);
        let wrapper = sign(&sender, &body);
        assert!(qtv_tx::verify(&wrapper, sender.public_key()));
        let signed = sign_payable_call(
            &seed,
            0,
            &target,
            vec![9, 9, 9],
            2500,
            4,
            1210,
            750,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        assert_eq!(signed.tx_bytes, to_bytes(&wrapper));
        assert_eq!(signed.tx_id, wrapper.id());
    }

    #[test]
    fn the_chain_id_and_fee_are_bound_into_the_signed_tx_and_cannot_be_swapped() {
        let seed = [7u8; SEED_LEN];
        let sender = derive(&seed, 0);
        let target = account_address(&seed, 1);

        let testnet =
            sign_transfer(&seed, 0, &target, 1000, 5, 500, testnet_chain_id(), 300).unwrap();
        let mainnet =
            sign_transfer(&seed, 0, &target, 1000, 5, 500, MAINNET_CHAIN_ID, 300).unwrap();
        assert_ne!(
            testnet.tx_bytes, mainnet.tx_bytes,
            "the chain id moves the signed bytes"
        );
        assert_ne!(testnet.tx_id, mainnet.tx_id);

        let cheap =
            sign_transfer(&seed, 0, &target, 1000, 5, 500, testnet_chain_id(), 300).unwrap();
        let dear = sign_transfer(&seed, 0, &target, 1000, 5, 999, testnet_chain_id(), 300).unwrap();
        assert_ne!(
            cheap.tx_bytes, dear.tx_bytes,
            "the fee moves the signed bytes"
        );

        let mut encoder = Encoder::new();
        encoder.put_u64(1000);
        let call = Call::new(target.clone(), encoder.into_bytes());
        let body = Body::with_context(
            sender.address(),
            5,
            NATIVE_TRANSFER_METER,
            500,
            call,
            0,
            testnet_chain_id(),
        );
        let wrapper = sign(&sender, &body);
        assert!(qtv_tx::verify(&wrapper, sender.public_key()));

        let swapped_chain = qtv_tx::Wrapper::new(
            Body::with_context(
                body.sender().to_string(),
                body.nonce(),
                body.meter_limit(),
                body.fee(),
                body.call().clone(),
                body.value(),
                MAINNET_CHAIN_ID,
            ),
            wrapper.scheme(),
            wrapper.signature().to_vec(),
        );
        assert!(
            !qtv_tx::verify(&swapped_chain, sender.public_key()),
            "the testnet signature must not verify for mainnet"
        );

        let swapped_fee = qtv_tx::Wrapper::new(
            Body::with_context(
                body.sender().to_string(),
                body.nonce(),
                body.meter_limit(),
                999,
                body.call().clone(),
                body.value(),
                testnet_chain_id(),
            ),
            wrapper.scheme(),
            wrapper.signature().to_vec(),
        );
        assert!(
            !qtv_tx::verify(&swapped_fee, sender.public_key()),
            "the testnet signature must not verify at a swapped fee"
        );
    }

    #[test]
    fn address_case_cannot_change_the_signature() {
        let seed = [7u8; SEED_LEN];
        let target = account_address(&seed, 1);
        let lowered = target.to_ascii_lowercase();
        assert_ne!(target, lowered);
        let upper = sign_call(
            &seed,
            0,
            &target,
            vec![4, 2],
            9,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        let lower = sign_call(
            &seed,
            0,
            &lowered,
            vec![4, 2],
            9,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500,
        )
        .unwrap();
        assert_eq!(upper.tx_bytes, lower.tx_bytes);
        assert_eq!(upper.tx_id, lower.tx_id);
    }

    #[test]
    fn a_deeply_nested_response_is_refused_not_crashed() {
        let deep = "[".repeat(100_000) + &"]".repeat(100_000);
        assert!(crate::json::parse(&deep).is_err());
        let deep_obj = "{\"a\":".repeat(100_000);
        assert!(crate::json::parse(&deep_obj).is_err());
    }

    #[test]
    fn bad_hex_is_a_clean_error_that_carries_no_input() {
        assert!(crate::json::from_hex("abc").is_err());
        let err = crate::json::from_hex("zz").unwrap_err();
        assert!(!err.contains('z'));
    }

    #[test]
    fn valid_address_accepts_a_derived_address_and_rejects_junk() {
        let address = account_address(&[7u8; SEED_LEN], 0);
        assert!(valid_address(&address));
        assert!(!valid_address("not an address"));
        assert!(!valid_address(""));
    }

    #[test]
    fn valid_address_rejects_a_payload_wider_than_the_canonical_address() {
        let canonical = account_address(&[7u8; SEED_LEN], 0);
        assert_eq!(
            qtv_idfmt::parse_address(&canonical).unwrap().len(),
            ADDRESS_PAYLOAD_LEN
        );
        assert!(valid_address(&canonical));
        assert!(
            qtv_idfmt::render_address(&[0x11u8; ADDRESS_PAYLOAD_LEN + 1]).is_err(),
            "an over wide payload can never be rendered into an address"
        );
        assert!(qtv_idfmt::render_address(&[0x11u8; ADDRESS_PAYLOAD_LEN + 8]).is_err());
        assert!(
            sign_transfer(
                &[7u8; SEED_LEN],
                0,
                "not an address",
                1000,
                0,
                500,
                LOCAL_CHAIN_ID,
                300
            )
            .is_err(),
            "a transfer to a non address target is refused before signing"
        );
        assert!(sign_call(
            &[7u8; SEED_LEN],
            0,
            "not an address",
            vec![1, 2],
            0,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500
        )
        .is_err());
    }

    #[test]
    fn a_bad_target_is_an_error_not_a_panic() {
        let seed = [7u8; SEED_LEN];
        assert!(sign_transfer(
            &seed,
            0,
            "not an address",
            1000,
            0,
            500,
            LOCAL_CHAIN_ID,
            300
        )
        .is_err());
        assert!(sign_call(
            &seed,
            0,
            "",
            vec![1, 2],
            0,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500
        )
        .is_err());
        assert!(sign_payable_call(
            &seed,
            0,
            "Q1zzz",
            vec![1],
            5,
            0,
            1210,
            500,
            LOCAL_CHAIN_ID,
            300,
            500
        )
        .is_err());
    }

    #[test]
    fn a_repeated_key_reads_the_last_value_like_a_browser() {
        let v = crate::json::parse("{\"n\":\"1\",\"n\":\"9\"}").unwrap();
        assert_eq!(v.get("n").and_then(crate::json::Json::as_str), Some("9"));
    }

    #[test]
    fn a_seed_round_trips_through_its_recovery_phrase() {
        let seed = [7u8; SEED_LEN];
        let phrase = mnemonic_from_seed(&seed);
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(*seed_from_mnemonic(&phrase).unwrap(), seed);
        assert_eq!(
            account_address(&seed_from_mnemonic(&phrase).unwrap(), 0),
            account_address(&seed, 0)
        );
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words[0] = if words[0] == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        assert!(seed_from_mnemonic(&words.join(" ")).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn a_url_client_refuses_a_mainnet_reporting_gateway_without_acknowledgement() {
        let info = |chain: &str| NodeInfo {
            chain_id: chain.to_string(),
            genesis_hash: String::new(),
            head_height: 0,
            denomination: String::new(),
            transfer_fee: 0,
            version: String::new(),
        };
        let client = Client::new("http://127.0.0.1:8645");
        assert!(
            client.signing_chain_id(&info(MAINNET_CHAIN_NAME)).is_err(),
            "a url client with no chosen network must refuse a mainnet reporting gateway"
        );
        assert!(
            client.signing_chain_id(&info("Q-test-net-1")).is_err(),
            "a url client must be configured before it signs for the public testnet"
        );
        assert!(
            client.signing_chain_id(&info("Q-dev-net-1")).is_ok(),
            "the same client still signs for a private dev chain"
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn a_configured_client_refuses_an_unacknowledged_mainnet_id_even_with_the_flag_off() {
        let info = |chain: &str| NodeInfo {
            chain_id: chain.to_string(),
            genesis_hash: String::new(),
            head_height: 0,
            denomination: String::new(),
            transfer_fee: 0,
            version: String::new(),
        };
        let mut network = Network::testnet();
        network.chain_id = Some(MAINNET_CHAIN_NAME.to_string());
        let client = Client::with_network("http://127.0.0.1:8645", network.clone(), false);
        assert!(
            client.signing_chain_id(&info(MAINNET_CHAIN_NAME)).is_err(),
            "a configured client must refuse a mainnet id it did not acknowledge, even with its is_mainnet flag off"
        );
        let acknowledged = Client::with_network("http://127.0.0.1:8645", network, true);
        assert!(
            acknowledged
                .signing_chain_id(&info(MAINNET_CHAIN_NAME))
                .is_ok(),
            "acknowledging mainnet lets the same configured client sign"
        );
    }
}
