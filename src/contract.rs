// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_account::{account_seed, SCHEME_LATTICE};
use qtv_crypto::{ml_dsa, sha3};
use qtv_wipe::Zeroizing;

use crate::json::{self, object, Json};

pub const CONTRACT_CONTEXT_BYTES: u64 = 120;

const WORD: u64 = 8;

const SIGNED_MSG_TAG: &[u8; 8] = b"QTVSGN01";
const NONCE_TAG: &[u8; 8] = b"QTVNONCE";

const MSG_TAG_OFF: usize = 0;
const MSG_CONTRACT_OFF: usize = 8;
const MSG_SELECTOR_OFF: usize = 40;
const MSG_SIGNER_OFF: usize = 48;
const MSG_NONCE_OFF: usize = 80;
const MSG_FIELDS_OFF: usize = 88;

pub const DEFAULT_REGION_OFFSET: u64 = 8192;

const MAX_USER_MEMORY: usize = 65536;

const DEPLOY_PARAMS_TAG: &[u8; 8] = b"QDEPLOY1";

const GENESIS_PARAM_SENTINEL: &[u8; 8] = b"QGENSNTL";

pub fn signer_address(scheme: u8, public_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + public_key.len());
    input.push(scheme);
    input.extend_from_slice(public_key);
    sha3::sha3_256(&input)
}

pub fn order_signer(owner_seed: &[u8; crate::SEED_LEN], owner_index: u64) -> [u8; 32] {
    let seed = Zeroizing::new(account_seed(owner_seed, SCHEME_LATTICE, owner_index));
    let (public_key, secret) = ml_dsa::keygen(&seed);
    let _secret = Zeroizing::new(secret);
    signer_address(SCHEME_LATTICE, &public_key)
}

pub fn nonce_slot_key(signer: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(NONCE_TAG.len() + 32);
    input.extend_from_slice(NONCE_TAG);
    input.extend_from_slice(signer);
    sha3::sha3_256(&input)
}

pub fn scalar_slot_key(slot: u64) -> [u8; 32] {
    qtv_vm::abi::scalar_key(slot)
}

pub fn map_slot_key(map_domain_tag: u64, key_address: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(WORD as usize + 32);
    input.extend_from_slice(&map_domain_tag.to_be_bytes());
    input.extend_from_slice(key_address);
    sha3::sha3_256(&input)
}

pub fn map_addr_word_key(map_domain_tag: u64, key_address: &[u8; 32], word: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(WORD as usize + 32 + WORD as usize);
    input.extend_from_slice(&map_domain_tag.to_be_bytes());
    input.extend_from_slice(key_address);
    input.extend_from_slice(&word.to_be_bytes());
    sha3::sha3_256(&input)
}

const NAME_WINDOW: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Word(u64),
    Wide([u8; 16]),
    Address([u8; 32]),
    Name(Vec<u8>),
}

impl FieldValue {
    pub fn name(label: &str) -> FieldValue {
        FieldValue::Name(label.as_bytes().to_vec())
    }

    pub fn wide(value: u128) -> FieldValue {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&(value as u64).to_be_bytes());
        out[8..].copy_from_slice(&((value >> 64) as u64).to_be_bytes());
        FieldValue::Wide(out)
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            FieldValue::Word(w) => w.to_be_bytes().to_vec(),
            FieldValue::Wide(b) => b.to_vec(),
            FieldValue::Address(a) => a.to_vec(),
            FieldValue::Name(label) => {
                let mut out = vec![0u8; NAME_WINDOW + WORD as usize];
                let n = label.len().min(NAME_WINDOW);
                out[..n].copy_from_slice(&label[..n]);
                out[NAME_WINDOW..].copy_from_slice(&(label.len() as u64).to_be_bytes());
                out
            }
        }
    }

    fn width(&self) -> u64 {
        match self {
            FieldValue::Word(_) => WORD,
            FieldValue::Wide(_) => 16,
            FieldValue::Address(_) => 32,
            FieldValue::Name(_) => NAME_WINDOW as u64 + WORD,
        }
    }

    fn ensure_fits(&self) -> Result<(), String> {
        if let FieldValue::Name(label) = self {
            if label.len() > NAME_WINDOW {
                return Err(
                    "a Q_Name label longer than thirty two bytes cannot be represented".to_string(),
                );
            }
        }
        Ok(())
    }
}

pub fn name_key(label: &str) -> [u8; 32] {
    sha3::sha3_256(label.as_bytes())
}

pub fn id_key(id: u64) -> [u8; 32] {
    let mut region = [0u8; 32];
    region[..WORD as usize].copy_from_slice(&id.to_be_bytes());
    region
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldArg {
    pub offset: u64,
    pub value: FieldValue,
}

pub fn canonical_order_message_typed(
    chain_id: u64,
    contract_id: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[FieldValue],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSG_FIELDS_OFF);
    debug_assert_eq!(msg.len(), MSG_TAG_OFF);
    let tag = u64::from_be_bytes(*SIGNED_MSG_TAG) ^ chain_id;
    msg.extend_from_slice(&tag.to_be_bytes());
    debug_assert_eq!(msg.len(), MSG_CONTRACT_OFF);
    msg.extend_from_slice(contract_id);
    debug_assert_eq!(msg.len(), MSG_SELECTOR_OFF);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    debug_assert_eq!(msg.len(), MSG_SIGNER_OFF);
    msg.extend_from_slice(signer);
    debug_assert_eq!(msg.len(), MSG_NONCE_OFF);
    msg.extend_from_slice(&nonce.to_be_bytes());
    debug_assert_eq!(msg.len(), MSG_FIELDS_OFF);
    for field in fields {
        msg.extend_from_slice(&field.bytes());
    }
    msg
}

pub fn canonical_order_message(
    chain_id: u64,
    contract_id: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let typed: Vec<FieldValue> = fields.iter().copied().map(FieldValue::Word).collect();
    canonical_order_message_typed(chain_id, contract_id, selector, signer, nonce, &typed)
}

#[derive(Debug, Clone)]
pub struct OrderLayout {
    pub scheme_off: u64,
    pub ptr_off: u64,
    pub field_offs: Vec<u64>,
    pub region_off: u64,
}

impl OrderLayout {
    pub fn new(scheme_off: u64, ptr_off: u64, field_offs: Vec<u64>) -> OrderLayout {
        OrderLayout {
            scheme_off,
            ptr_off,
            field_offs,
            region_off: DEFAULT_REGION_OFFSET,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedOrderCall {
    pub call_args: Vec<u8>,
    pub user_memory: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signer: [u8; 32],
    pub nonce: u64,
}

#[allow(clippy::too_many_arguments)]
#[derive(Debug, Clone)]
pub struct TypedField {
    pub offset: u64,
    pub width: u64,
    pub value: String,
}

fn field_value_of_width(width: u64, value: &str) -> Result<FieldValue, String> {
    match width {
        w if w == WORD => value
            .parse::<u64>()
            .map(FieldValue::Word)
            .map_err(|_| "a word field value is not a whole number".to_string()),
        16 => value
            .parse::<u128>()
            .map(FieldValue::wide)
            .map_err(|_| "a wide field value is not a whole number".to_string()),
        32 => {
            let bytes = crate::json::from_hex(value)?;
            let addr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "an address field is thirty two bytes of hex".to_string())?;
            Ok(FieldValue::Address(addr))
        }
        _ => Err(format!("a signed field width of {width} is not supported")),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_order_from_typed(
    chain_id: u64,
    contract: &str,
    selector: [u8; 4],
    scheme_off: u64,
    ptr_off: u64,
    region_off: u64,
    fields: &[TypedField],
    owner_seed: &[u8; crate::SEED_LEN],
    owner_index: u64,
    nonce: u64,
) -> Result<SignedOrderCall, String> {
    let typed: Result<Vec<FieldArg>, String> = fields
        .iter()
        .map(|f| {
            Ok(FieldArg {
                offset: f.offset,
                value: field_value_of_width(f.width, &f.value)?,
            })
        })
        .collect();
    build_typed_order_call(
        chain_id,
        contract,
        selector,
        scheme_off,
        ptr_off,
        region_off,
        &typed?,
        owner_seed,
        owner_index,
        nonce,
    )
}

pub fn build_signed_order_call(
    chain_id: u64,
    contract: &str,
    selector: [u8; 4],
    layout: &OrderLayout,
    fields: &[u64],
    owner_seed: &[u8; crate::SEED_LEN],
    owner_index: u64,
    nonce: u64,
) -> Result<SignedOrderCall, String> {
    if fields.len() != layout.field_offs.len() {
        return Err(format!(
            "the order carries {} field values but the entry layout expects {}",
            fields.len(),
            layout.field_offs.len()
        ));
    }
    let typed: Vec<FieldArg> = layout
        .field_offs
        .iter()
        .zip(fields)
        .map(|(off, value)| FieldArg {
            offset: *off,
            value: FieldValue::Word(*value),
        })
        .collect();
    build_typed_order_call(
        chain_id,
        contract,
        selector,
        layout.scheme_off,
        layout.ptr_off,
        layout.region_off,
        &typed,
        owner_seed,
        owner_index,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_typed_order_call(
    chain_id: u64,
    contract: &str,
    selector: [u8; 4],
    scheme_off: u64,
    ptr_off: u64,
    region_off: u64,
    fields: &[FieldArg],
    owner_seed: &[u8; crate::SEED_LEN],
    owner_index: u64,
    nonce: u64,
) -> Result<SignedOrderCall, String> {
    let region_off = if region_off == 0 {
        DEFAULT_REGION_OFFSET
    } else {
        region_off
    };
    let contract_id = contract_id(contract)?;
    if scheme_off < CONTRACT_CONTEXT_BYTES || ptr_off < CONTRACT_CONTEXT_BYTES {
        return Err("the scheme or pointer offset falls inside the host call context".to_string());
    }
    for field in fields {
        field.value.ensure_fits()?;
        if field.offset < CONTRACT_CONTEXT_BYTES {
            return Err("a field offset falls inside the host call context".to_string());
        }
    }

    let seed = Zeroizing::new(account_seed(owner_seed, SCHEME_LATTICE, owner_index));
    let (public_key, secret) = ml_dsa::keygen(&seed);
    let secret = Zeroizing::new(secret);
    debug_assert_eq!(
        public_key.len(),
        qtv_vm::abi::ML_DSA_PUBLIC_KEY_BYTES,
        "the derived public key length must be the machine's module lattice public key length"
    );

    let signer = signer_address(SCHEME_LATTICE, &public_key);
    let values: Vec<FieldValue> = fields.iter().map(|f| f.value.clone()).collect();
    let message =
        canonical_order_message_typed(chain_id, &contract_id, selector, &signer, nonce, &values);

    let signature = ml_dsa::sign(&secret, &message, &[], &[0u8; 32])
        .ok_or("signing the order message failed")?;
    debug_assert_eq!(
        signature.len(),
        qtv_vm::abi::ML_DSA_SIGNATURE_BYTES,
        "the signature length must be the machine's module lattice signature length"
    );

    let region_start = usize::try_from(region_off).map_err(|_| "the region offset is too large")?;
    let region_len = public_key.len() + signature.len() + message.len();
    let region_end = region_start
        .checked_add(region_len)
        .ok_or("the verify region overflows the address space")?;

    let mut last_word_end = CONTRACT_CONTEXT_BYTES
        .max(
            scheme_off
                .checked_add(WORD)
                .ok_or("the scheme offset is too large")?,
        )
        .max(
            ptr_off
                .checked_add(WORD)
                .ok_or("the pointer offset is too large")?,
        );
    for field in fields {
        let end = field
            .offset
            .checked_add(field.value.width())
            .ok_or("a field offset is too large")?;
        last_word_end = last_word_end.max(end);
    }
    let mem_len =
        region_end.max(usize::try_from(last_word_end).map_err(|_| "a field offset is too large")?);
    if mem_len > MAX_USER_MEMORY {
        return Err("the order arguments do not fit the contract memory".to_string());
    }

    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(fields.len() + 3);
    spans.push((scheme_off, WORD));
    spans.push((ptr_off, WORD));
    for field in fields {
        spans.push((field.offset, field.value.width()));
    }
    spans.push((region_off, region_len as u64));
    spans.sort_by_key(|span| span.0);
    for pair in spans.windows(2) {
        let end = pair[0]
            .0
            .checked_add(pair[0].1)
            .ok_or("a call span overflows the argument memory")?;
        if end > pair[1].0 {
            return Err(
                "the order layout overlaps the verify region or a signed field".to_string(),
            );
        }
    }

    let mut user_memory = vec![0u8; mem_len];

    put_word(&mut user_memory, scheme_off, u64::from(SCHEME_LATTICE))?;
    put_word(&mut user_memory, ptr_off, region_off)?;
    for field in fields {
        put_bytes(&mut user_memory, field.offset, &field.value.bytes())?;
    }

    let pk_end = region_start + public_key.len();
    let sig_end = pk_end + signature.len();
    user_memory[region_start..pk_end].copy_from_slice(&public_key);
    user_memory[pk_end..sig_end].copy_from_slice(&signature);
    user_memory[sig_end..region_end].copy_from_slice(&message);

    let mut call_args = Vec::with_capacity(selector.len() + user_memory.len());
    call_args.extend_from_slice(&selector);
    call_args.extend_from_slice(&user_memory);

    Ok(SignedOrderCall {
        call_args,
        user_memory,
        message,
        signature: signature.to_vec(),
        public_key: public_key.to_vec(),
        signer,
        nonce,
    })
}

pub fn build_call_args(selector: [u8; 4], args: &[FieldArg]) -> Result<Vec<u8>, String> {
    let mut mem_len = CONTRACT_CONTEXT_BYTES;
    for field in args {
        field.value.ensure_fits()?;
        if field.offset < CONTRACT_CONTEXT_BYTES {
            return Err("an argument offset falls inside the host call context".to_string());
        }
        let end = field
            .offset
            .checked_add(field.value.width())
            .ok_or("an argument offset is too large")?;
        mem_len = mem_len.max(end);
    }
    let mem_len = usize::try_from(mem_len).map_err(|_| "an argument offset is too large")?;
    if mem_len > MAX_USER_MEMORY {
        return Err("the call arguments do not fit the contract memory".to_string());
    }
    let mut user_memory = vec![0u8; mem_len];
    for field in args {
        put_bytes(&mut user_memory, field.offset, &field.value.bytes())?;
    }
    let mut call_args = Vec::with_capacity(selector.len() + user_memory.len());
    call_args.extend_from_slice(&selector);
    call_args.extend_from_slice(&user_memory);
    Ok(call_args)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployParam {
    Address([u8; 32]),
    U64(u64),
    U128(u128),
    Guardians(Vec<[u8; 32]>),
}

impl DeployParam {
    fn bytes(&self) -> Vec<u8> {
        match self {
            DeployParam::Address(a) => a.to_vec(),
            DeployParam::U64(v) => v.to_be_bytes().to_vec(),
            DeployParam::U128(v) => {
                let mut out = Vec::with_capacity(16);
                out.extend_from_slice(&(*v as u64).to_be_bytes());
                out.extend_from_slice(&((*v >> 64) as u64).to_be_bytes());
                out
            }
            DeployParam::Guardians(gs) => {
                let mut out = Vec::with_capacity(gs.len() * 32);
                for g in gs {
                    out.extend_from_slice(g);
                }
                out
            }
        }
    }
}

pub fn build_deploy_call(container: &[u8], params: &[DeployParam]) -> Vec<u8> {
    let mut region = Vec::new();
    for param in params {
        region.extend_from_slice(&param.bytes());
    }
    if !params.is_empty() {
        region.extend_from_slice(GENESIS_PARAM_SENTINEL);
    }
    let mut out = Vec::with_capacity(DEPLOY_PARAMS_TAG.len() + 4 + container.len() + region.len());
    out.extend_from_slice(DEPLOY_PARAMS_TAG);
    out.extend_from_slice(&(container.len() as u32).to_be_bytes());
    out.extend_from_slice(container);
    out.extend_from_slice(&region);
    out
}

fn contract_id(contract: &str) -> Result<[u8; 32], String> {
    let payload =
        qtv_idfmt::parse_address(contract).map_err(|_| "the contract is not a Q1 address")?;
    payload
        .as_slice()
        .try_into()
        .map_err(|_| "the contract address is not the canonical thirty two byte width".to_string())
}

fn put_word(memory: &mut [u8], offset: u64, value: u64) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|_| "an argument offset is too large")?;
    let end = start
        .checked_add(WORD as usize)
        .ok_or("an argument word overflows scratch")?;
    memory
        .get_mut(start..end)
        .ok_or("an argument word runs off the end of the argument memory")?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_bytes(memory: &mut [u8], offset: u64, bytes: &[u8]) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|_| "an argument offset is too large")?;
    let end = start
        .checked_add(bytes.len())
        .ok_or("an argument value overflows scratch")?;
    memory
        .get_mut(start..end)
        .ok_or("an argument value runs off the end of the argument memory")?
        .copy_from_slice(bytes);
    Ok(())
}

pub fn storage_body(address: &str) -> String {
    object(vec![("address", Json::str(address))]).render()
}

pub fn events_body(height: u64) -> String {
    object(vec![("height", Json::Int(height))]).render()
}

pub const TOKEN_DECIMALS_SLOT: u64 = 0;
pub const TOKEN_SYMBOL_SLOT: u64 = 1;

pub fn pack_symbol(symbol: &str) -> u64 {
    let mut out = [0u8; 8];
    let bytes = symbol.as_bytes();
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_be_bytes(out)
}

pub fn unpack_symbol(word: u64) -> String {
    let bytes = word.to_be_bytes();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn asset_balance_body(issuer: &str, holder: &str) -> String {
    object(vec![
        ("issuer", Json::str(issuer)),
        ("holder", Json::str(holder)),
    ])
    .render()
}

pub fn asset_supply_body(issuer: &str) -> String {
    object(vec![("issuer", Json::str(issuer))]).render()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlot {
    pub slot: [u8; 32],
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEvent {
    pub contract: String,
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

pub fn parse_storage(response: &str) -> Result<Vec<StorageSlot>, String> {
    let v = json::parse(response)?;
    let items = v
        .get("slots")
        .and_then(Json::as_array)
        .ok_or("the storage response has no slots array")?;
    let mut slots = Vec::with_capacity(items.len());
    for item in items {
        let slot_hex = item
            .get("slot")
            .and_then(Json::as_str)
            .ok_or("a storage slot has no slot key")?;
        let bytes = json::from_hex(slot_hex)?;
        let slot: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "a storage slot key is not thirty two bytes".to_string())?;
        let value = item
            .get("value")
            .and_then(Json::as_str)
            .ok_or("a storage slot has no value")?
            .parse::<u64>()
            .map_err(|_| "a storage slot value is not a whole number".to_string())?;
        slots.push(StorageSlot { slot, value });
    }
    Ok(slots)
}

pub fn storage_value(slots: &[StorageSlot], key: &[u8; 32]) -> u64 {
    slots
        .iter()
        .find(|slot| &slot.slot == key)
        .map(|slot| slot.value)
        .unwrap_or(0)
}

pub fn parse_events(response: &str) -> Result<Vec<ContractEvent>, String> {
    let v = json::parse(response)?;
    let items = v
        .get("events")
        .and_then(Json::as_array)
        .ok_or("the events response has no events array")?;
    let mut events = Vec::with_capacity(items.len());
    for item in items {
        let contract = item
            .get("contract")
            .and_then(Json::as_str)
            .ok_or("an event has no contract")?
            .to_string();
        let selector_bytes = json::from_hex(
            item.get("selector")
                .and_then(Json::as_str)
                .ok_or("an event has no selector")?,
        )?;
        let selector: [u8; 4] = selector_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "an event selector is not four bytes".to_string())?;
        let data = json::from_hex(
            item.get("data")
                .and_then(Json::as_str)
                .ok_or("an event has no data")?,
        )?;
        events.push(ContractEvent {
            contract,
            selector,
            data,
        });
    }
    Ok(events)
}

pub fn event_word(data: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = data.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symbol_round_trips_through_the_metadata_word() {
        for symbol in ["LTK", "USDC", "WBTC", "wstETH", "Q"] {
            assert_eq!(unpack_symbol(pack_symbol(symbol)), symbol);
        }
        assert_eq!(pack_symbol("LTK"), 0x4c54_4b00_0000_0000);
        assert_eq!(pack_symbol("toolongsymbol"), pack_symbol("toolongs"));
    }

    const BUMP_SELECTOR: [u8; 4] = [0x6c, 0xad, 0x12, 0xfc];
    const BUMPED_SELECTOR: [u8; 4] = [0x6e, 0x82, 0x53, 0x1d];

    const TEST_CHAIN: u64 = 0x0123_4567_89AB_CDEF;

    fn counter_layout() -> OrderLayout {
        OrderLayout::new(120, 128, vec![136])
    }

    #[test]
    fn a_bad_contract_address_names_the_uppercase_q1_form() {
        let err = super::contract_id("not an address").unwrap_err();
        assert!(err.contains("Q1 address"));
    }

    #[test]
    fn the_signer_address_is_the_account_address_payload() {
        let seed = [5u8; crate::SEED_LEN];
        let signer = order_signer(&seed, 0);
        let address = crate::account_address(&seed, 0);
        let payload = qtv_idfmt::parse_address(&address).unwrap();
        assert_eq!(&signer[..], payload.as_slice());
    }

    #[test]
    fn the_layout_matches_the_emit_offsets_and_the_words_land_there() {
        let seed = [7u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let layout = counter_layout();
        let order = build_signed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            &layout,
            &[5],
            &seed,
            0,
            0,
        )
        .unwrap();

        assert_eq!(word_at(&order.user_memory, 120), u64::from(SCHEME_LATTICE));
        assert_eq!(word_at(&order.user_memory, 128), DEFAULT_REGION_OFFSET);
        assert_eq!(word_at(&order.user_memory, 136), 5);

        assert!(order.user_memory[..CONTRACT_CONTEXT_BYTES as usize]
            .iter()
            .all(|&b| b == 0));

        assert_eq!(&order.call_args[..4], &BUMP_SELECTOR);
        assert_eq!(&order.call_args[4..], &order.user_memory[..]);
    }

    #[test]
    fn the_verify_region_is_public_key_then_signature_then_message() {
        let seed = [9u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let order = build_signed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            &counter_layout(),
            &[3],
            &seed,
            0,
            0,
        )
        .unwrap();
        let base = DEFAULT_REGION_OFFSET as usize;
        let pk = order.public_key.len();
        let sig = order.signature.len();
        assert_eq!(&order.user_memory[base..base + pk], &order.public_key[..]);
        assert_eq!(
            &order.user_memory[base + pk..base + pk + sig],
            &order.signature[..]
        );
        assert_eq!(
            &order.user_memory[base + pk + sig..base + pk + sig + order.message.len()],
            &order.message[..]
        );
    }

    #[test]
    fn the_message_is_the_canonical_order_and_the_owner_signature_verifies() {
        let seed = [3u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let signer = order_signer(&seed, 0);
        let contract_id = super::contract_id(&contract).unwrap();
        let expected =
            canonical_order_message(TEST_CHAIN, &contract_id, BUMP_SELECTOR, &signer, 7, &[42]);
        let order = build_signed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            &counter_layout(),
            &[42],
            &seed,
            0,
            7,
        )
        .unwrap();
        assert_eq!(order.message, expected);
        assert_eq!(
            order.message.len(),
            96,
            "tag 8, contract 32, selector 8, signer 32, nonce 8, one field 8"
        );

        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
    }

    const PINNED_ORDER_PREIMAGE: [u8; 96] = [
        0x50, 0x77, 0x13, 0x34, 0xce, 0xe5, 0xfd, 0xde, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x6c,
        0xad, 0x12, 0xfc, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,
    ];

    #[test]
    fn an_order_bound_to_one_chain_differs_on_another() {
        let contract = [0x33; 32];
        let signer = [0x11; 32];
        let a = canonical_order_message(7, &contract, BUMP_SELECTOR, &signer, 3, &[42]);
        let b = canonical_order_message(9, &contract, BUMP_SELECTOR, &signer, 3, &[42]);
        assert_ne!(
            a, b,
            "the same order under two chains signs a different preimage"
        );
        assert_eq!(a[8..], b[8..], "only the chain bound tag word differs");
        let unbound = canonical_order_message(0, &contract, BUMP_SELECTOR, &signer, 3, &[42]);
        assert_eq!(
            &unbound[..8],
            SIGNED_MSG_TAG,
            "a zero chain leaves the bare domain tag"
        );
    }

    #[test]
    fn the_order_preimage_matches_the_pinned_chain_bound_vector() {
        let preimage = canonical_order_message(
            0x0123_4567_89AB_CDEF,
            &[0x33; 32],
            BUMP_SELECTOR,
            &[0x11; 32],
            7,
            &[42],
        );
        assert_eq!(
            preimage.len(),
            96,
            "tag 8, contract 32, selector 8, signer 32, nonce 8, field 8"
        );
        assert_eq!(preimage.as_slice(), PINNED_ORDER_PREIMAGE.as_slice());
        assert_eq!(
            &preimage[..8],
            &(u64::from_be_bytes(*SIGNED_MSG_TAG) ^ 0x0123_4567_89AB_CDEF).to_be_bytes(),
            "the leading word is the domain tag xored with the chain id"
        );
    }

    #[test]
    fn the_nonce_slot_key_matches_the_hashed_preimage() {
        let signer = [0x11u8; 32];
        let mut preimage = b"QTVNONCE".to_vec();
        preimage.extend_from_slice(&signer);
        assert_eq!(nonce_slot_key(&signer), sha3::sha3_256(&preimage));
    }

    #[test]
    fn a_field_count_mismatch_is_refused_before_signing() {
        let seed = [1u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        assert!(build_signed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            &counter_layout(),
            &[1, 2],
            &seed,
            0,
            0
        )
        .is_err());
    }

    #[test]
    fn storage_and_events_responses_parse() {
        let count_key = scalar_slot_key(4);
        let count_hex: String = count_key.iter().map(|b| format!("{b:02x}")).collect();
        let response = format!(
            "{{\"address\":\"q1x\",\"slots\":[{{\"slot\":\"{count_hex}\",\"value\":\"5\"}}]}}"
        );
        let slots = parse_storage(&response).unwrap();
        assert_eq!(storage_value(&slots, &count_key), 5);
        assert_eq!(storage_value(&slots, &scalar_slot_key(9)), 0);

        let events = parse_events(
            "{\"height\":3,\"count\":1,\"events\":[{\"contract\":\"q1c\",\"selector\":\"6e82531d\",\"data\":\"0000000000000005\"}]}",
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].selector, BUMPED_SELECTOR);
        assert_eq!(event_word(&events[0].data), Some(5));
    }

    fn word_at(memory: &[u8], off: usize) -> u64 {
        u64::from_be_bytes(memory[off..off + 8].try_into().unwrap())
    }

    const MINT_SELECTOR: [u8; 4] = [0x3e, 0xcc, 0xb9, 0xbc];

    #[test]
    fn a_typed_order_binds_a_wide_u128_field_at_full_width() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let amount: u128 = (1u128 << 64) + 100;
        let fields = vec![
            FieldArg {
                offset: 168,
                value: FieldValue::wide(amount),
            },
            FieldArg {
                offset: 136,
                value: FieldValue::Address(to),
            },
        ];
        let order = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap();

        assert_eq!(
            order.message.len(),
            88 + 16 + 32,
            "the wide amount widens the preimage to 136 bytes"
        );
        assert_eq!(
            &order.message[88..96],
            &100u64.to_be_bytes(),
            "the amount low word is first"
        );
        assert_eq!(
            &order.message[96..104],
            &1u64.to_be_bytes(),
            "the amount high word is second"
        );
        assert_eq!(
            &order.message[104..136],
            &to,
            "the address follows the wide amount"
        );
        assert_eq!(
            word_at(&order.user_memory, 168),
            100,
            "the argument region carries the low word"
        );
        assert_eq!(word_at(&order.user_memory, 176), 1, "then the high word");
        assert_eq!(&order.user_memory[136..168], &to);
        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
    }

    #[test]
    fn build_order_from_typed_binds_a_wide_field_by_its_descriptor_width() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let to_hex: String = to.iter().map(|b| format!("{b:02x}")).collect();
        let fields = vec![
            TypedField {
                offset: 168,
                width: 16,
                value: "18446744073709551716".to_string(),
            },
            TypedField {
                offset: 136,
                width: 32,
                value: to_hex,
            },
        ];
        let order = build_order_from_typed(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            order.message.len(),
            88 + 16 + 32,
            "the descriptor width widens the preimage"
        );
        assert_eq!(&order.message[88..96], &100u64.to_be_bytes());
        assert_eq!(&order.message[96..104], &1u64.to_be_bytes());
        assert_eq!(&order.message[104..136], &to);
        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
    }

    #[test]
    fn a_zero_region_offset_falls_back_to_the_default_and_does_not_clobber_the_signed_fields() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let to_hex: String = to.iter().map(|b| format!("{b:02x}")).collect();
        let fields = vec![
            TypedField {
                offset: 168,
                width: 16,
                value: "18446744073709551716".to_string(),
            },
            TypedField {
                offset: 136,
                width: 32,
                value: to_hex,
            },
        ];
        let order = build_order_from_typed(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            0,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap();
        let mem = &order.call_args[4..];
        assert_eq!(
            &mem[136..168],
            &to,
            "the executable recipient matches the signed recipient"
        );
        assert_eq!(&order.message[104..136], &to);
        let base = DEFAULT_REGION_OFFSET as usize;
        assert_eq!(
            &mem[base..base + order.public_key.len()],
            &order.public_key[..],
            "the region lands at the default, clear of the fields"
        );
        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
    }

    #[test]
    fn a_field_overlapping_the_verify_region_is_refused_not_clobbered() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let to_hex: String = to.iter().map(|b| format!("{b:02x}")).collect();
        let fields = vec![
            TypedField {
                offset: 136,
                width: 16,
                value: "500".to_string(),
            },
            TypedField {
                offset: DEFAULT_REGION_OFFSET,
                width: 32,
                value: to_hex,
            },
        ];
        let err = build_order_from_typed(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("overlaps the verify region"), "got: {err}");
    }

    #[test]
    fn a_field_fully_contained_in_another_field_is_refused() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let fields = vec![
            FieldArg {
                offset: 136,
                value: FieldValue::Address([0u8; 32]),
            },
            FieldArg {
                offset: 140,
                value: FieldValue::Word(1),
            },
        ];
        let err = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("overlaps the verify region"), "got: {err}");
    }

    #[test]
    fn a_three_way_overlap_is_refused() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let fields = vec![
            FieldArg {
                offset: 136,
                value: FieldValue::Address([0u8; 32]),
            },
            FieldArg {
                offset: 144,
                value: FieldValue::Word(1),
            },
            FieldArg {
                offset: 150,
                value: FieldValue::Word(1),
            },
        ];
        let err = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("overlaps the verify region"), "got: {err}");
    }

    #[test]
    fn a_field_overlapping_the_scheme_or_pointer_word_is_refused() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let fields = vec![FieldArg {
            offset: 128,
            value: FieldValue::Word(1),
        }];
        let err = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("overlaps the verify region"), "got: {err}");
    }

    #[test]
    fn a_field_offset_past_the_contract_memory_is_refused_not_allocated() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let fields = vec![TypedField {
            offset: 1 << 40,
            width: 8,
            value: "1".to_string(),
        }];
        let err = build_order_from_typed(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("do not fit the contract memory"), "got: {err}");
        let args = vec![FieldArg {
            offset: 1 << 40,
            value: FieldValue::Word(1),
        }];
        let err = build_call_args(MINT_SELECTOR, &args).unwrap_err();
        assert!(err.contains("do not fit the contract memory"), "got: {err}");
    }

    #[test]
    fn a_typed_order_binds_a_word_and_a_whole_address_field() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let fields = vec![
            FieldArg {
                offset: 168,
                value: FieldValue::Word(500),
            },
            FieldArg {
                offset: 136,
                value: FieldValue::Address(to),
            },
        ];
        let order = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            MINT_SELECTOR,
            120,
            128,
            DEFAULT_REGION_OFFSET,
            &fields,
            &seed,
            0,
            0,
        )
        .unwrap();

        assert_eq!(order.message.len(), 88 + 8 + 32);
        assert_eq!(&order.message[88..96], &500u64.to_be_bytes());
        assert_eq!(&order.message[96..128], &to);

        assert_eq!(word_at(&order.user_memory, 168), 500);
        assert_eq!(&order.user_memory[136..168], &to);
        assert_eq!(word_at(&order.user_memory, 120), u64::from(SCHEME_LATTICE));
        assert_eq!(word_at(&order.user_memory, 128), DEFAULT_REGION_OFFSET);

        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
    }

    #[test]
    fn the_word_only_builder_matches_the_typed_core() {
        let seed = [8u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let layout = counter_layout();
        let word = build_signed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            &layout,
            &[7],
            &seed,
            0,
            3,
        )
        .unwrap();
        let typed = build_typed_order_call(
            TEST_CHAIN,
            &contract,
            BUMP_SELECTOR,
            layout.scheme_off,
            layout.ptr_off,
            layout.region_off,
            &[FieldArg {
                offset: 136,
                value: FieldValue::Word(7),
            }],
            &seed,
            0,
            3,
        )
        .unwrap();
        assert_eq!(word.call_args, typed.call_args);
        assert_eq!(word.message, typed.message);
    }

    #[test]
    fn build_call_args_places_typed_fields_and_leaves_the_context_zero() {
        let to = [0x2Cu8; 32];
        let selector = [0xb8, 0x4d, 0xbd, 0x2c];
        let args = build_call_args(
            selector,
            &[
                FieldArg {
                    offset: 120,
                    value: FieldValue::Address(to),
                },
                FieldArg {
                    offset: 152,
                    value: FieldValue::Word(200),
                },
            ],
        )
        .unwrap();
        assert_eq!(&args[..4], &selector);
        let mem = &args[4..];
        assert!(
            mem[..CONTRACT_CONTEXT_BYTES as usize]
                .iter()
                .all(|&b| b == 0),
            "context left for the node"
        );
        assert_eq!(&mem[120..152], &to);
        assert_eq!(word_at(mem, 152), 200);
    }

    #[test]
    fn a_name_field_places_the_label_window_then_the_length_word() {
        let selector = [0x2d, 0xfb, 0xa5, 0xfc];
        let args = build_call_args(
            selector,
            &[
                FieldArg {
                    offset: 120,
                    value: FieldValue::name("alice"),
                },
                FieldArg {
                    offset: 160,
                    value: FieldValue::Word(2),
                },
            ],
        )
        .unwrap();
        let mem = &args[4..];
        assert!(
            mem[..CONTRACT_CONTEXT_BYTES as usize]
                .iter()
                .all(|&b| b == 0),
            "context stays for the node"
        );
        assert_eq!(&mem[120..125], b"alice", "the label bytes lead the window");
        assert!(
            mem[125..152].iter().all(|&b| b == 0),
            "the window tail is zero padded"
        );
        assert_eq!(
            word_at(mem, 152),
            5,
            "the length word sits directly after the window"
        );
        assert_eq!(
            word_at(mem, 160),
            2,
            "the following word argument lands after the name"
        );
        assert_eq!(name_key("alice"), sha3::sha3_256(b"alice"));
    }

    #[test]
    fn a_name_label_wider_than_the_window_is_refused_not_truncated() {
        let selector = [0x2d, 0xfb, 0xa5, 0xfc];
        let long = "a".repeat(NAME_WINDOW + 1);
        let err = build_call_args(
            selector,
            &[FieldArg {
                offset: 120,
                value: FieldValue::name(&long),
            }],
        )
        .unwrap_err();
        assert!(
            err.contains("thirty two bytes"),
            "an over wide label is refused, not silently truncated"
        );
        let exact = "a".repeat(NAME_WINDOW);
        assert!(build_call_args(
            selector,
            &[FieldArg {
                offset: 120,
                value: FieldValue::name(&exact)
            }]
        )
        .is_ok());
    }

    #[test]
    fn a_token_id_promotes_to_the_leading_word_of_a_zeroed_region() {
        let region = id_key(7);
        assert_eq!(
            &region[..8],
            &7u64.to_be_bytes(),
            "the id leads the region big endian"
        );
        assert!(
            region[8..].iter().all(|&b| b == 0),
            "the rest of the region is zero"
        );
        assert_ne!(
            id_key(1),
            id_key(2),
            "distinct ids promote to distinct regions"
        );
        let base: u64 = 1 << 40;
        assert_eq!(map_slot_key(base, &id_key(7)), {
            let mut input = base.to_be_bytes().to_vec();
            input.extend_from_slice(&id_key(7));
            sha3::sha3_256(&input)
        });
    }

    #[test]
    fn a_deploy_call_frames_the_container_and_the_params_with_a_sentinel() {
        let container = b"QVM1 the whole container bytes".to_vec();
        let owner = [0x55u8; 32];
        let supply: u128 = (7u128 << 64) | 0x1234;
        let args = build_deploy_call(
            &container,
            &[DeployParam::Address(owner), DeployParam::U128(supply)],
        );
        assert_eq!(&args[..8], DEPLOY_PARAMS_TAG);
        assert_eq!(
            u32::from_be_bytes(args[8..12].try_into().unwrap()) as usize,
            container.len()
        );
        let cstart = 12;
        let cend = cstart + container.len();
        assert_eq!(&args[cstart..cend], &container[..]);
        let region = &args[cend..];
        assert_eq!(&region[..32], &owner);
        assert_eq!(&region[32..40], &(supply as u64).to_be_bytes());
        assert_eq!(&region[40..48], &((supply >> 64) as u64).to_be_bytes());
        assert_eq!(&region[48..56], GENESIS_PARAM_SENTINEL);
        assert_eq!(region.len(), 56);
    }

    #[test]
    fn a_paramless_deploy_carries_no_sentinel() {
        let container = b"QVM1 body".to_vec();
        let args = build_deploy_call(&container, &[]);
        assert_eq!(args.len(), 8 + 4 + container.len());
    }

    #[test]
    fn a_guardian_set_deploy_param_lays_out_its_addresses_inline() {
        let gs = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let args = build_deploy_call(b"QVM1", &[DeployParam::Guardians(gs.clone())]);
        let region = &args[8 + 4 + 4..];
        for (j, g) in gs.iter().enumerate() {
            assert_eq!(&region[j * 32..j * 32 + 32], g);
        }
        assert_eq!(&region[96..104], GENESIS_PARAM_SENTINEL);
    }
}
