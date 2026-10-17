// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod contract;
pub mod finality;
pub mod json;

#[cfg(feature = "client")]
mod http;

use json::{object, to_hex, Json};
use qtv_account::derive;
use qtv_codec::{to_bytes, Encoder};
use qtv_tx::{try_sign, Body, Call};
use qtv_wipe::Zeroizing;

pub use qtv_tx::{
    chain_id_from_name, LOCAL_CHAIN_ID, LOCAL_CHAIN_NAME, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME,
};

pub const TESTNET_CHAIN_NAME: &str = "Q-test-net-1";

pub const SEED_LEN: usize = 32;

pub const MAX_PLAUSIBLE_HEAD: u64 = 1 << 40;

pub const HEAD_BLOCKS_PER_SEC: u64 = 20;

pub const HEAD_SLACK_BLOCKS: u64 = 240;

pub const GENESIS_FLOOR_SECS: u64 = 1_735_689_600;

pub const TESTNET_GENESIS_SECS: u64 = 1_791_082_813;

pub const TESTNET_RPC_URL: &str = "https://rpc-testnet.quantova.org";

pub const ADDRESS_PAYLOAD_LEN: usize = 32;

pub const NATIVE_TRANSFER_METER: u64 = 1_210;

pub const MAX_METER_LIMIT: u64 = 12_500_000;

pub const MAX_DEPLOY_METER_LIMIT: u64 = 50_000_000;

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
            rpc_url: Some(TESTNET_RPC_URL.to_string()),
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
    check_call_to(target, meter_limit, args.len(), fee, transfer_fee)?;
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
    check_call_under(MAX_METER_LIMIT, meter_limit, args_len, fee, transfer_fee)
}

pub fn check_call_to(
    target: &str,
    meter_limit: u64,
    args_len: usize,
    fee: u128,
    transfer_fee: u128,
) -> Result<(), String> {
    let ceiling = if target == vm_deploy_address() {
        MAX_DEPLOY_METER_LIMIT
    } else {
        MAX_METER_LIMIT
    };
    check_call_under(ceiling, meter_limit, args_len, fee, transfer_fee)
}

fn check_call_under(
    ceiling: u64,
    meter_limit: u64,
    args_len: usize,
    fee: u128,
    transfer_fee: u128,
) -> Result<(), String> {
    if !(NATIVE_TRANSFER_METER..=ceiling).contains(&meter_limit) {
        return Err(format!(
            "the meter limit {meter_limit} is outside the range {NATIVE_TRANSFER_METER} to {ceiling} the chain admits, refusing to sign"
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

pub fn genesis_secs(chain_name: &str) -> u64 {
    if chain_name == TESTNET_CHAIN_NAME {
        TESTNET_GENESIS_SECS
    } else {
        GENESIS_FLOOR_SECS
    }
}

pub fn head_ceiling(chain_name: &str, wall_secs: u64) -> u64 {
    wall_secs
        .saturating_sub(genesis_secs(chain_name))
        .saturating_mul(HEAD_BLOCKS_PER_SEC)
        .saturating_add(HEAD_SLACK_BLOCKS)
}

pub fn bounded_valid_until(
    chain_name: &str,
    head: u64,
    wall_secs: u64,
    floor: Option<u64>,
    floor_age_secs: u64,
) -> Result<u64, String> {
    if head > MAX_PLAUSIBLE_HEAD {
        return Err(format!(
            "the gateway reports head {head}, past any height this chain can have reached, refusing to sign"
        ));
    }
    if head > head_ceiling(chain_name, wall_secs) {
        return Err(format!(
            "the gateway reports head {head} further ahead than wall-clock time allows, refusing to sign"
        ));
    }
    if let Some(floor) = floor {
        if head < floor {
            return Err(format!(
                "the gateway reports head {head} below the {floor} it reported earlier, refusing to sign"
            ));
        }
        let allowed = floor_age_secs
            .saturating_mul(HEAD_BLOCKS_PER_SEC)
            .saturating_add(HEAD_SLACK_BLOCKS);
        if head > floor.saturating_add(allowed) {
            return Err(format!(
                "the gateway head leapt from {floor} to {head} faster than blocks are made, refusing to sign"
            ));
        }
    }
    let valid_until = head.saturating_add(DEFAULT_VALIDITY_BLOCKS);
    check_valid_until(valid_until, head)?;
    Ok(valid_until)
}

pub fn checked_chain_id(name: &str) -> Result<u64, String> {
    if name.is_empty() {
        return Err("a chain name is required to derive a chain id".to_string());
    }
    Ok(chain_id_from_name(name))
}

pub fn canonical_decimal(text: &str) -> Option<u128> {
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    whole_number(text)
}

pub fn whole_number(text: &str) -> Option<u128> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub fn check_gateway_json(response: &str) -> Result<(), String> {
    json::parse(response).map(|_| ())
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
    let wrapper = try_sign(&sender, &body)
        .ok_or_else(|| "the sender or the target is not a q1 address".to_string())?;
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
    if amount == 0 {
        return Err("an asset transfer of zero is refused, the chain rejects it".to_string());
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
    let wrapper = try_sign(&sender, &body)
        .ok_or_else(|| "the sender or the target is not a q1 address".to_string())?;
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
    whole_number(&field_str(v, key)?)
        .ok_or_else(|| format!("the {key} field is not a number string"))
}

fn field_u8(v: &Json, key: &str) -> Result<u8, String> {
    let n = field_u64(v, key)?;
    u8::try_from(n).map_err(|_| format!("the {key} field is out of range for a byte"))
}

pub fn valid_address(address: &str) -> bool {
    matches!(qtv_idfmt::parse_address(address), Ok(payload) if payload.len() == ADDRESS_PAYLOAD_LEN)
}

pub const LOOKALIKE_EDGE: usize = 2;

pub const LOOKALIKE_SPAN: usize = 8;

pub fn same_address(a: &str, b: &str) -> bool {
    matches!((address_payload(a), address_payload(b)), (Ok(x), Ok(y)) if x == y)
}

fn shares_edges(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_uppercase(), b.to_ascii_uppercase());
    let (Some(a), Some(b)) = (a.get(2..), b.get(2..)) else {
        return false;
    };
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let head = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let tail = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    head >= LOOKALIKE_EDGE && tail >= LOOKALIKE_EDGE && head + tail >= LOOKALIKE_SPAN
}

pub fn lookalike_of(candidate: &str, known: &[String]) -> Option<String> {
    let target = address_payload(candidate).ok()?;
    known.iter().find_map(|other| {
        let payload = address_payload(other).ok()?;
        (payload != target && shares_edges(candidate, other)).then(|| other.clone())
    })
}

pub const SESSION_REMEMBERED_ADDRESSES: usize = 1024;

#[derive(Debug, Default, Clone)]
pub struct SigningSession {
    next: std::collections::HashMap<String, u64>,
    held: std::collections::HashMap<String, std::collections::BTreeMap<u64, bool>>,
    book: Vec<String>,
    seen: std::collections::VecDeque<String>,
}

impl SigningSession {
    pub fn new() -> SigningSession {
        SigningSession::default()
    }

    pub fn with_address_book(book: &[String]) -> Result<SigningSession, String> {
        let mut session = SigningSession::new();
        for address in book {
            if !valid_address(address) {
                return Err(format!(
                    "the address book entry {address} is not a Q1 address"
                ));
            }
            session.book.push(address.clone());
        }
        Ok(session)
    }

    pub fn known(&self) -> Vec<String> {
        self.book.iter().chain(self.seen.iter()).cloned().collect()
    }

    pub fn remember_address(&mut self, address: &str) {
        if !valid_address(address)
            || self
                .book
                .iter()
                .chain(self.seen.iter())
                .any(|known| same_address(known, address))
        {
            return;
        }
        if self.seen.len() >= SESSION_REMEMBERED_ADDRESSES {
            self.seen.pop_front();
        }
        self.seen.push_back(address.to_string());
    }

    pub fn check_target(&self, address: &str) -> Result<(), String> {
        let near = self.book.iter().chain(self.seen.iter()).find(|known| {
            !same_address(known, address)
                && valid_address(known)
                && valid_address(address)
                && shares_edges(address, known)
        });
        match near {
            Some(near) => Err(format!(
                "the address {address} shares its leading and trailing characters with {near}, which this client already knows, but is a different address, refusing to sign for a lookalike"
            )),
            None => Ok(()),
        }
    }

    pub fn slot(
        &mut self,
        key: &str,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, String> {
        if let Some(exp) = expected {
            if exp != reported {
                return Err(format!(
                    "the gateway reported nonce {reported} but you expected {exp}; the chain admits \
                     only the nonce the account has reached, refusing to sign"
                ));
            }
        }
        let held = self.held.entry(key.to_string()).or_default();
        held.retain(|slot, accepted| !(*accepted && *slot < reported));
        if expected.is_some() {
            held.retain(|slot, _| *slot > reported);
        } else {
            if order {
                if let Some(local) = self.next.get(key).copied() {
                    if reported > local {
                        return Err(format!(
                            "the gateway reports order nonce {reported} above the {local} this client tracked, \
                             refusing to sign an order that stays valid until the contract reaches that nonce; \
                             pass the expected order nonce to sign at it"
                        ));
                    }
                }
            }
            if held.contains_key(&reported) {
                return Err(format!(
                    "a transaction was already signed for nonce {reported} in this session and was not \
                     superseded; one nonce carries one signature, so if it never landed pass that nonce \
                     explicitly to sign at it again"
                ));
            }
            if let Some((&stale, _)) = held
                .iter()
                .find(|(slot, accepted)| **slot < reported && !**accepted)
            {
                return Err(format!(
                    "a transaction signed at nonce {stale} in this session was not accepted, yet the \
                     gateway now reports nonce {reported} past it; check whether it landed, then pass \
                     nonce {reported} explicitly to sign at it"
                ));
            }
        }
        let local = self.next.entry(key.to_string()).or_insert(reported);
        *local = (*local).max(reported);
        Ok(reported)
    }

    pub fn signed(&mut self, key: &str, slot: u64) {
        self.held
            .entry(key.to_string())
            .or_default()
            .insert(slot, false);
    }

    pub fn outcome(&mut self, key: &str, slot: u64, accepted: bool) {
        if !accepted {
            return;
        }
        self.held
            .entry(key.to_string())
            .or_default()
            .insert(slot, true);
        let local = self.next.entry(key.to_string()).or_insert(0);
        *local = (*local).max(slot.saturating_add(1));
    }

    pub fn next_nonce(&self, key: &str) -> Option<u64> {
        self.next.get(key).copied()
    }

    pub fn is_held(&self, key: &str, slot: u64) -> bool {
        self.held
            .get(key)
            .is_some_and(|held| held.contains_key(&slot))
    }
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

pub const PHRASE_CHECKSUM_BITS: usize = 19;
pub const PHRASE_WORDS: usize = (SEED_LEN * 8 + PHRASE_CHECKSUM_BITS) / 11;

fn checksum_bit(seed: &[u8; SEED_LEN], i: usize) -> u8 {
    let digest = qtv_crypto::sha3::sha3_256(seed);
    (digest[i / 8] >> (7 - i % 8)) & 1
}

pub fn mnemonic_from_seed(seed: &[u8; SEED_LEN]) -> Zeroizing<String> {
    let words = word_list();
    let mut bits: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(SEED_LEN * 8 + PHRASE_CHECKSUM_BITS));
    for &byte in seed.iter() {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    for i in 0..PHRASE_CHECKSUM_BITS {
        bits.push(checksum_bit(seed, i));
    }
    let mut phrase = String::with_capacity(PHRASE_WORDS * 9);
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

const STANDARD_PHRASE: &str = "this phrase carries a standard BIP-39 checksum and is not a twenty five word Quantova recovery phrase, so it cannot restore a Quantova account";

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
            .binary_search(word)
            .map_err(|_| "a word in the phrase is not in the word list")?;
        for shift in (0..11).rev() {
            bits.push(((index >> shift) & 1) as u8);
        }
    }
    if entered.len() != PHRASE_WORDS {
        if is_standard_phrase(&bits) {
            return Err(STANDARD_PHRASE.to_string());
        }
        return Err("a recovery phrase is twenty five words".to_string());
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&bits_to_bytes(&bits[..SEED_LEN * 8]));
    let checksum_ok =
        (0..PHRASE_CHECKSUM_BITS).all(|i| bits[SEED_LEN * 8 + i] == checksum_bit(&seed, i));
    if !checksum_ok {
        if is_standard_phrase(&bits) {
            return Err(STANDARD_PHRASE.to_string());
        }
        return Err("the recovery phrase checksum does not match, check for a typo".to_string());
    }
    Ok(seed)
}

pub fn seed_from_mnemonic_bytes(phrase: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, String> {
    let text = Zeroizing::new(
        std::str::from_utf8(phrase)
            .map_err(|_| "the recovery phrase is not UTF-8 text".to_string())?
            .to_string(),
    );
    seed_from_mnemonic(&text)
}

pub fn mnemonic_bytes_from_seed(seed: &[u8; SEED_LEN]) -> Zeroizing<Vec<u8>> {
    let phrase = mnemonic_from_seed(seed);
    Zeroizing::new(phrase.as_bytes().to_vec())
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
pub use client::{Client, Transport};

#[cfg(feature = "client")]
mod client {
    fn order_clock() -> Result<u64, String> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| "the system clock is before 1970".to_string())
    }

    use super::*;

    fn order_slot_key(contract: &str, signer: &[u8; 32]) -> String {
        let hex: String = signer.iter().map(|b| format!("{b:02x}")).collect();
        format!("{contract}/{hex}")
    }

    pub trait Transport {
        fn post(&self, base: &str, path: &str, body: &str) -> Result<(u16, String), String>;
    }

    struct LoopbackHttp;

    impl Transport for LoopbackHttp {
        fn post(&self, base: &str, path: &str, body: &str) -> Result<(u16, String), String> {
            http::post(base, path, body)
        }
    }

    pub struct Client {
        base: String,
        network: Network,
        acknowledge_mainnet: bool,
        transport: Box<dyn Transport>,
        pinned_chain: std::cell::RefCell<Option<String>>,
        head_floor: std::cell::Cell<Option<(u64, std::time::Instant)>>,
        session: std::cell::RefCell<SigningSession>,
    }

    fn fresh(base: String, network: Network, acknowledge_mainnet: bool) -> Client {
        Client {
            base: normalize_base(base),
            network,
            acknowledge_mainnet,
            transport: Box::new(LoopbackHttp),
            pinned_chain: std::cell::RefCell::new(None),
            head_floor: std::cell::Cell::new(None),
            session: std::cell::RefCell::new(SigningSession::new()),
        }
    }

    fn normalize_base(base: String) -> String {
        base.trim_end_matches('/').to_string()
    }

    fn accepted(outcome: &Submit) -> bool {
        matches!(outcome, Submit::Accepted { .. })
    }

    impl Client {
        pub fn new(base: impl Into<String>) -> Client {
            let base = base.into();
            let network = Network::for_url(base.clone());
            fresh(base, network, false)
        }

        pub fn for_network(network: Network, acknowledge_mainnet: bool) -> Result<Client, String> {
            let base = Self::network_base(&network, acknowledge_mainnet)?;
            if !base.starts_with("http://") {
                return Err(format!(
                    "the {} network is served at {base}, and the built in transport reaches only a plaintext loopback node, so open it with Client::for_network_with_transport and a TLS transport, or pass a loopback endpoint with Client::with_network",
                    network.name
                ));
            }
            Ok(fresh(base, network, acknowledge_mainnet))
        }

        pub fn for_network_with_transport(
            network: Network,
            acknowledge_mainnet: bool,
            transport: Box<dyn Transport>,
        ) -> Result<Client, String> {
            let base = Self::network_base(&network, acknowledge_mainnet)?;
            Ok(fresh(base, network, acknowledge_mainnet).with_transport(transport))
        }

        fn network_base(network: &Network, acknowledge_mainnet: bool) -> Result<String, String> {
            let base = network.rpc_url.clone().ok_or_else(|| {
                format!(
                    "the {} network has no rpc endpoint yet, pass the endpoint explicitly with Client::with_network",
                    network.name
                )
            })?;
            if network.is_mainnet && !acknowledge_mainnet {
                return Err("refusing to open a mainnet client without acknowledging it, a mainnet transaction moves real value so the network must be chosen on purpose".to_string());
            }
            Ok(base)
        }

        pub fn with_network(
            base: impl Into<String>,
            network: Network,
            acknowledge_mainnet: bool,
        ) -> Client {
            fresh(base.into(), network, acknowledge_mainnet)
        }

        pub fn with_transport(mut self, transport: Box<dyn Transport>) -> Client {
            self.transport = transport;
            self
        }

        pub fn with_address_book(self, book: &[String]) -> Result<Client, String> {
            *self.session.borrow_mut() = SigningSession::with_address_book(book)?;
            Ok(self)
        }

        pub fn network(&self) -> &Network {
            &self.network
        }

        pub fn session(&self) -> SigningSession {
            self.session.borrow().clone()
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

        fn vet_target(&self, sender: &str, targets: &[&str]) -> Result<(), String> {
            let mut session = self.session.borrow_mut();
            session.remember_address(sender);
            for target in targets {
                session.check_target(target)?;
            }
            Ok(())
        }

        fn remember_targets(&self, targets: &[&str]) {
            let mut session = self.session.borrow_mut();
            for target in targets {
                session.remember_address(target);
            }
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
            let (status, text) =
                self.transport
                    .post(&self.base, &format!("/v1/{method}"), &body)?;
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
            let sender = account_address(seed, index);
            self.vet_target(&sender, &[to])?;
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
            let nonce = self.checked_nonce(&sender, expected_nonce)?;
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
            self.remember_targets(&[to]);
            let outcome = self.submit_held(&[(&sender, nonce)], &signed)?;
            Ok((signed, outcome))
        }

        fn checked_nonce(&self, sender: &str, expected: Option<u64>) -> Result<u64, String> {
            let account = self.account(sender)?;
            self.session
                .borrow_mut()
                .slot(sender, account.nonce, expected, false)
        }

        fn submit_held(
            &self,
            slots: &[(&str, u64)],
            signed: &SignedTransfer,
        ) -> Result<Submit, String> {
            {
                let mut session = self.session.borrow_mut();
                for (key, slot) in slots {
                    session.signed(key, *slot);
                }
            }
            let outcome = self.submit(&signed.tx_bytes)?;
            let mut session = self.session.borrow_mut();
            for (key, slot) in slots {
                session.outcome(key, *slot, accepted(&outcome));
            }
            Ok(outcome)
        }

        fn validity(&self, info: &NodeInfo) -> Result<u64, String> {
            let head = info.head_height;
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let now = std::time::Instant::now();
            let floor = self.head_floor.get();
            let valid_until = bounded_valid_until(
                &info.chain_id,
                head,
                wall,
                floor.map(|(height, _)| height),
                floor
                    .map(|(_, at)| now.duration_since(at).as_secs())
                    .unwrap_or(0),
            )?;
            if floor.is_none_or(|(height, _)| head > height) {
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
            let sender = account_address(seed, index);
            self.vet_target(&sender, &[target])?;
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let nonce = self.checked_nonce(&sender, expected_nonce)?;
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
            self.remember_targets(&[target]);
            let outcome = self.submit_held(&[(&sender, nonce)], &signed)?;
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
            if !valid_address(target) {
                return Err("the target is not a Q1 address".to_string());
            }
            if !valid_address(asset_issuer) {
                return Err("the asset issuer is not a Q1 address".to_string());
            }
            let sender = account_address(seed, index);
            self.vet_target(&sender, &[target, asset_issuer])?;
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let nonce = self.checked_nonce(&sender, expected_nonce)?;
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
            self.remember_targets(&[target, asset_issuer]);
            let outcome = self.submit_held(&[(&sender, nonce)], &signed)?;
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
            crate::contract::storage_value_reported(
                &self.storage_at(contract, std::slice::from_ref(key))?,
                key,
            )
            .ok_or_else(|| "the gateway did not report the requested storage slot".to_string())
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
            contract::check_order_expiry(layout.expiry, order_clock()?)?;
            let caller = account_address(caller_seed, caller_index);
            self.vet_target(&caller, &[contract])?;
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let order_key = order_slot_key(contract, &signer);
            let reported = self.contract_nonce(contract, &signer)?;
            let nonce =
                self.session
                    .borrow_mut()
                    .slot(&order_key, reported, expected_order_nonce, true)?;
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
            let account_nonce = self.checked_nonce(&caller, expected_nonce)?;
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
            self.remember_targets(&[contract]);
            let outcome =
                self.submit_held(&[(&order_key, nonce), (&caller, account_nonce)], &signed)?;
            Ok((signed, outcome, order))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_typed_order(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            layout_hash: &[u8; contract::LAYOUT_HASH_BYTES],
            scheme_off: u64,
            ptr_off: u64,
            expiry_off: u64,
            expiry: u64,
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
                layout_hash,
                scheme_off,
                ptr_off,
                expiry_off,
                expiry,
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
            layout_hash: &[u8; contract::LAYOUT_HASH_BYTES],
            scheme_off: u64,
            ptr_off: u64,
            expiry_off: u64,
            expiry: u64,
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
            if in_asset.is_some_and(|issuer| !valid_address(issuer)) {
                return Err("the asset issuer is not a Q1 address".to_string());
            }
            contract::check_order_expiry(expiry, order_clock()?)?;
            let caller = account_address(caller_seed, caller_index);
            let mut targets = vec![contract];
            targets.extend(in_asset);
            self.vet_target(&caller, &targets)?;
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let order_key = order_slot_key(contract, &signer);
            let reported = self.contract_nonce(contract, &signer)?;
            let nonce =
                self.session
                    .borrow_mut()
                    .slot(&order_key, reported, expected_order_nonce, true)?;
            let order = contract::build_typed_order_call(
                chain_id,
                contract,
                selector,
                layout_hash,
                scheme_off,
                ptr_off,
                expiry_off,
                region_off,
                fields,
                owner_seed,
                owner_index,
                nonce,
                expiry,
            )?;
            let account_nonce = self.checked_nonce(&caller, expected_nonce)?;
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
            self.remember_targets(&targets);
            let outcome =
                self.submit_held(&[(&order_key, nonce), (&caller, account_nonce)], &signed)?;
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
            let deployer = account_address(seed, index);
            self.vet_target(&deployer, &[])?;
            let info = self.node_info()?;
            self.guard_mainnet()?;
            let fee = self.fee_within(vm_call_fee(info.transfer_fee, meter_limit), max_fee)?;
            let chain_id = self.signing_chain_id(&info)?;
            let valid_until = self.validity(&info)?;
            let account_nonce = self.checked_nonce(&deployer, expected_nonce)?;
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
            let outcome = self.submit_held(&[(&deployer, account_nonce)], &signed)?;
            if accepted(&outcome) {
                self.remember_targets(&[&contract]);
            }
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
            let sender = account_address(seed, index);
            self.vet_target(&sender, &[])?;
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
            let nonce = self.checked_nonce(&sender, expected_nonce)?;
            let signed =
                sign_register(seed, index, nonce, info.transfer_fee, chain_id, valid_until)?;
            let outcome = self.submit_held(&[(&sender, nonce)], &signed)?;
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

        #[test]
        fn an_expected_nonce_must_be_the_reported_one() {
            let mut session = SigningSession::new();
            assert!(session.slot("b", 9, Some(3), false).is_err());
            assert!(
                session.slot("b", 2, Some(3), false).is_err(),
                "the mempool admits only the nonce the account has reached, so a slot ahead of it is refused"
            );
            assert_eq!(session.slot("b", 3, Some(3), false).unwrap(), 3);
        }

        #[test]
        fn the_local_nonce_follows_the_highest_reported_one_rather_than_refusing() {
            let mut session = SigningSession::new();
            assert_eq!(session.slot("a", 4, None, false).unwrap(), 4);
            session.signed("a", 4);
            session.outcome("a", 4, true);
            assert_eq!(session.next_nonce("a"), Some(5));
            assert_eq!(
                session.slot("a", 9, None, false).unwrap(),
                9,
                "a gateway ahead of the local nonce raises it once every signed slot was accepted"
            );
            assert_eq!(session.next_nonce("a"), Some(9));
            assert!(
                !session.is_held("a", 4),
                "an accepted slot below the reported nonce is consumed"
            );
        }

        #[test]
        fn a_signed_nonce_is_held_until_the_caller_names_it_again() {
            let mut session = SigningSession::new();
            session.slot("a", 4, None, false).unwrap();
            session.signed("a", 4);
            assert!(
                session.slot("a", 4, None, false).is_err(),
                "a slot already signed this session is not signed again unnamed"
            );
            session.outcome("a", 4, false);
            assert!(
                session.slot("a", 4, None, false).is_err(),
                "a gateway-asserted rejection does not free a signed slot"
            );
            assert!(
                session.slot("a", 5, None, false).is_err(),
                "a gateway reporting the next nonce after rejecting the signed one is refused"
            );
            assert_eq!(
                session.slot("a", 4, Some(4), false).unwrap(),
                4,
                "naming the slot is how a caller says the first never landed"
            );
            session.signed("a", 4);
            session.outcome("a", 4, true);
            assert!(
                session.slot("a", 4, None, false).is_err(),
                "an accepted slot the chain has not passed is still held"
            );
            assert_eq!(session.slot("a", 5, None, false).unwrap(), 5);
        }

        #[test]
        fn an_order_nonce_above_the_tracked_one_needs_the_caller() {
            let mut session = SigningSession::new();
            assert_eq!(session.slot("o", 2, None, true).unwrap(), 2);
            assert!(
                session.slot("o", 7, None, true).is_err(),
                "an order nonce the gateway raised on its own is refused"
            );
            assert_eq!(session.slot("o", 7, Some(7), true).unwrap(), 7);
        }

        #[test]
        fn a_lookalike_of_a_known_address_is_refused() {
            let own = account_address(&[3u8; 32], 0);
            let mut session =
                SigningSession::with_address_book(std::slice::from_ref(&own)).unwrap();
            assert!(session.check_target(&own).is_ok());
            let mut fake = None;
            let mut payload = address_payload(&own).unwrap();
            for i in 0..1_000_000u32 {
                payload[28..].copy_from_slice(&i.to_le_bytes());
                let candidate = qtv_idfmt::render_address(&payload).unwrap();
                if candidate != own && candidate[candidate.len() - 2..] == own[own.len() - 2..] {
                    fake = Some(candidate);
                    break;
                }
            }
            let fake =
                fake.expect("two trailing characters are cheap to match under a shared prefix");
            assert!(session.check_target(&fake).is_err());
            session.remember_address(&fake);
            assert!(SigningSession::with_address_book(&["junk".to_string()]).is_err());
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
            assert!(!configured.session.borrow().is_held(&sender, 0));
            let client = Client::new(base);
            assert!(client.transfer(&seed, 0, &to, 5, 500).is_err());
            assert!(client
                .transfer(&seed, 0, &sender, 5, 500)
                .unwrap_err()
                .contains("self transfer"));
            assert!(
                !client.session.borrow().is_held(&sender, 0),
                "a chain, head or signing refusal must not hold the nonce it never signed"
            );
            assert_eq!(client.session.borrow().next_nonce(&sender), Some(0));
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
        let deploy = |meter: u64| {
            sign_call(
                &seed,
                0,
                &vm_deploy_address(),
                vec![1],
                0,
                meter,
                vm_call_fee(500, meter),
                LOCAL_CHAIN_ID,
                300,
                500,
            )
        };
        assert!(deploy(MAX_METER_LIMIT + 1).is_ok());
        assert!(deploy(MAX_DEPLOY_METER_LIMIT).is_ok());
        assert!(deploy(MAX_DEPLOY_METER_LIMIT + 1).is_err());
        assert_eq!(MAX_DEPLOY_METER_LIMIT, 50_000_000);
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
    fn lookalike_edges_score_the_leading_and_trailing_characters_together() {
        let a = "Q1ABCDEF0000000000000000000000000000000000000000000000UVWXYZ";
        let with = |head: &str, tail: &str| {
            let middle = "1".repeat(a.len() - 2 - head.len() - tail.len());
            format!("Q1{head}{middle}{tail}")
        };
        assert!(shares_edges(a, &with("ABCD", "WXYZ")));
        assert!(shares_edges(a, &with("AB", "UVWXYZ")));
        assert!(shares_edges(a, &with("ABCDEF", "YZ")));
        assert!(shares_edges(a, &a.to_ascii_lowercase()));
        assert!(!shares_edges(a, &with("ABC", "WXYZ")));
        assert!(!shares_edges(a, &with("A", "TUVWXYZ")));
        assert!(!shares_edges(a, &with("ABCDEFG", "Z")));
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
        let typo = ["abandon"; 25].join(" ");
        assert!(seed_from_mnemonic(&typo)
            .unwrap_err()
            .contains("check for a typo"));
        let short = ["abandon"; 12].join(" ");
        assert!(seed_from_mnemonic(&short)
            .unwrap_err()
            .contains("twenty five words"));
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
        let wrapper = try_sign(&sender, &body).expect("the test addresses parse");
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
        let wrapper = try_sign(&sender, &body).expect("the test addresses parse");
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
    fn a_repeated_key_is_refused() {
        assert!(crate::json::parse("{\"n\":\"1\",\"n\":\"9\"}").is_err());
    }

    #[test]
    fn a_seed_round_trips_through_its_recovery_phrase() {
        let seed = [7u8; SEED_LEN];
        let phrase = mnemonic_from_seed(&seed);
        assert_eq!(phrase.split_whitespace().count(), 25);
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

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn the_wire_parser_refuses_what_strict_json_refuses() {
        assert!(json::parse("{\"n\":007}").is_err());
        assert!(json::parse("{\"n\":0}").is_ok());
        assert!(json::parse("{\"n\":1.0}").is_err());
        assert!(json::parse("{\"n\":1e3}").is_err());
        assert!(json::parse("{\"n\":-1}").is_err());
        assert!(json::parse("{\"s\":\"a\u{1}b\"}").is_err());
        assert!(json::parse("{\"s\":\"a\\u0001b\"}").is_ok());
        assert!(check_gateway_json("\u{feff}{}").is_err());
    }

    #[test]
    fn a_gateway_number_string_is_plain_ascii_digits() {
        assert_eq!(whole_number("500"), Some(500));
        for bad in ["", "+500", " 500", "500 ", "5_00", "-5", "\u{0665}", "0x10"] {
            assert_eq!(whole_number(bad), None, "{bad:?}");
        }
        let info = |fee: &str| {
            format!(
                "{{\"chain_id\":\"c\",\"genesis_hash\":\"g\",\"head_height\":1,\"denomination\":\"Quon\",\"fee\":{{\"transfer_quon\":\"{fee}\"}},\"version\":\"v\"}}"
            )
        };
        assert!(parse_node_info(&info("500")).is_ok());
        assert!(parse_node_info(&info("+500")).is_err());
    }

    #[test]
    fn the_head_bound_follows_the_network_genesis() {
        let at = TESTNET_GENESIS_SECS + 1_000;
        let ceiling = head_ceiling(TESTNET_CHAIN_NAME, at);
        assert_eq!(ceiling, 1_000 * HEAD_BLOCKS_PER_SEC + HEAD_SLACK_BLOCKS);
        assert!(bounded_valid_until(TESTNET_CHAIN_NAME, ceiling, at, None, 0).is_ok());
        assert!(bounded_valid_until(TESTNET_CHAIN_NAME, ceiling + 1, at, None, 0).is_err());
        assert_eq!(
            head_ceiling(TESTNET_CHAIN_NAME, TESTNET_GENESIS_SECS - 5),
            HEAD_SLACK_BLOCKS,
            "a clock before genesis allows only the slack, never an unbounded head"
        );
        assert!(bounded_valid_until("Q-dev-net-1", 1_000, at, Some(1_000), 0).is_ok());
        assert!(bounded_valid_until("Q-dev-net-1", 999, at, Some(1_000), 0).is_err());
        assert!(bounded_valid_until(
            "Q-dev-net-1",
            1_000 + HEAD_SLACK_BLOCKS + 1,
            at,
            Some(1_000),
            0
        )
        .is_err());
        const { assert!(HEAD_SLACK_BLOCKS < DEFAULT_VALIDITY_BLOCKS) };
    }

    #[test]
    fn a_phrase_round_trips_through_byte_buffers() {
        let seed = [9u8; SEED_LEN];
        let phrase = mnemonic_bytes_from_seed(&seed);
        assert_eq!(*seed_from_mnemonic_bytes(&phrase).unwrap(), seed);
        assert!(seed_from_mnemonic_bytes(&[0xff, 0xfe]).is_err());
    }
}
