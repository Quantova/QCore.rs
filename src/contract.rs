//! The client side contract call ABI.

use qtv_account::{account_seed, SCHEME_LATTICE};
use qtv_crypto::{ml_dsa, sha3};

use crate::json::{self, object, Json};

/// The trusted execution context the node injects at the front of contract scratch memory before an
pub const CONTRACT_CONTEXT_BYTES: u64 = 72;

/// The byte width of a machine word.
const WORD: u64 = 8;

/// The domain tag of the canonical signed order message. A signature over the message can be reused for
const SIGNED_MSG_TAG: &[u8; 8] = b"QTVSGN01";
/// The domain tag of the per signer nonce slot preimage, separating a nonce slot from any other hashed
const NONCE_TAG: &[u8; 8] = b"QTVNONCE";

// Byte offsets of each field of the canonical order message, relative to the message start. They are
// the compiler's own `MSG_*_OFF` constants: the domain tag, the contract self address, the entry
// selector word, the signer address, the per signer nonce, then the committed order field words.
const MSG_TAG_OFF: usize = 0;
const MSG_CONTRACT_OFF: usize = 8;
const MSG_SELECTOR_OFF: usize = 40;
const MSG_SIGNER_OFF: usize = 48;
const MSG_NONCE_OFF: usize = 80;
const MSG_FIELDS_OFF: usize = 88;

/// A default byte offset in scratch memory for the verify region, the public key then signature then
pub const DEFAULT_REGION_OFFSET: u64 = 8192;

/// The signer address the chain, the machine's ADDR opcode, and a contract's signed prologue all
pub fn signer_address(scheme: u8, public_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + public_key.len());
    input.push(scheme);
    input.extend_from_slice(public_key);
    sha3::sha3_256(&input)
}

/// The signer address of the module lattice account a seed and index derive, the owner an order is
pub fn order_signer(owner_seed: &[u8; crate::SEED_LEN], owner_index: u64) -> [u8; 32] {
    let seed = account_seed(owner_seed, SCHEME_LATTICE, owner_index);
    let (public_key, _secret) = ml_dsa::keygen(&seed);
    signer_address(SCHEME_LATTICE, &public_key)
}

/// The full thirty two byte storage key of the per signer nonce slot, the SHA3-256 of the nonce domain
pub fn nonce_slot_key(signer: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(NONCE_TAG.len() + 32);
    input.extend_from_slice(NONCE_TAG);
    input.extend_from_slice(signer);
    sha3::sha3_256(&input)
}

/// The full thirty two byte storage key of a scalar state field slot, twenty four zero bytes then the
pub fn scalar_slot_key(slot: u64) -> [u8; 32] {
    qtv_vm::abi::scalar_key(slot)
}

/// The full thirty two byte storage key of a keyed map entry, the SHA3-256 of the map's eight byte
pub fn map_slot_key(map_domain_tag: u64, key_address: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(WORD as usize + 32);
    input.extend_from_slice(&map_domain_tag.to_be_bytes());
    input.extend_from_slice(key_address);
    sha3::sha3_256(&input)
}

/// The canonical order message a `signed by owner` order commits to, rebuilt byte for byte the way the
pub fn canonical_order_message(
    contract_id: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSG_FIELDS_OFF + fields.len() * WORD as usize);
    debug_assert_eq!(msg.len(), MSG_TAG_OFF);
    msg.extend_from_slice(SIGNED_MSG_TAG);
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
        msg.extend_from_slice(&field.to_be_bytes());
    }
    msg
}

/// The argument layout of one `signed by owner` entry, read from the compiler's emit output. The scheme
#[derive(Debug, Clone)]
pub struct OrderLayout {
    /// The `<name>#scheme` argument word offset, carrying the one byte signature scheme identifier.
    pub scheme_off: u64,
    /// The `<name>#ptr` argument word offset, carrying the byte offset of the verify region.
    pub ptr_off: u64,
    /// The order field word offsets, in the first appearance order the canonical message commits to.
    pub field_offs: Vec<u64>,
    /// Where the verify region is laid out in scratch memory. [`DEFAULT_REGION_OFFSET`] is a safe
    pub region_off: u64,
}

impl OrderLayout {
    /// The layout of an entry with one signed order, its scheme and pointer words and its field words,
    pub fn new(scheme_off: u64, ptr_off: u64, field_offs: Vec<u64>) -> OrderLayout {
        OrderLayout {
            scheme_off,
            ptr_off,
            field_offs,
            region_off: DEFAULT_REGION_OFFSET,
        }
    }
}

/// A built and signed order call: the argument bytes to submit, and the parts that went into it so a
#[derive(Debug, Clone)]
pub struct SignedOrderCall {
    /// The call arguments a contract call transaction carries: the four byte entry selector followed by
    pub call_args: Vec<u8>,
    /// The argument memory alone, the bytes the node places into scratch after overwriting the trusted
    pub user_memory: Vec<u8>,
    /// The canonical order message the signature is over, the exact bytes the contract rebuilds.
    pub message: Vec<u8>,
    /// The module lattice signature over the message.
    pub signature: Vec<u8>,
    /// The owner's public key, at the start of the verify region.
    pub public_key: Vec<u8>,
    /// The signer address the order binds to, SHA3-256 of the scheme byte and the public key.
    pub signer: [u8; 32],
    /// The per signer nonce the order carries.
    pub nonce: u64,
}

/// Lay out and sign a module lattice `signed by owner` order call. Given the contract, the entry
pub fn build_signed_order_call(
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
    let contract_id = contract_id(contract)?;

    // Derive the owner's module lattice key, its public key at the region start and its secret to sign
    // with. The expanded secret is derived here and dropped when this returns.
    let seed = account_seed(owner_seed, SCHEME_LATTICE, owner_index);
    let (public_key, secret) = ml_dsa::keygen(&seed);
    debug_assert_eq!(
        public_key.len(),
        qtv_vm::abi::ML_DSA_PUBLIC_KEY_BYTES,
        "the derived public key length must be the machine's module lattice public key length"
    );

    let signer = signer_address(SCHEME_LATTICE, &public_key);
    let message = canonical_order_message(&contract_id, selector, &signer, nonce, fields);

    // Sign the rebuilt message under an empty context, the way the machine's ML-DSA verify opcode
    // checks it. Any valid signature over these bytes verifies, so the fixed randomness only fixes the
    // bytes, not the acceptance.
    let signature = ml_dsa::sign(&secret, &message, &[], &[0u8; 32])
        .ok_or("signing the order message failed")?;
    debug_assert_eq!(
        signature.len(),
        qtv_vm::abi::ML_DSA_SIGNATURE_BYTES,
        "the signature length must be the machine's module lattice signature length"
    );

    // The verify region: the public key, then the signature, then the message. The contract rebuilds
    // the message in place over these same bytes before it verifies, so it must fit inside the region
    // and inside scratch, which the region offset and the machine's scratch size guarantee.
    let region_off = usize::try_from(layout.region_off).map_err(|_| "the region offset is too large")?;
    let region_len = public_key.len() + signature.len() + message.len();
    let region_end = region_off
        .checked_add(region_len)
        .ok_or("the verify region overflows the address space")?;

    // The argument memory spans the trusted context, the argument words, and the verify region. It is
    // sized to hold the whole region, which for a module lattice order sits far above the words.
    let last_word_end = layout
        .field_offs
        .iter()
        .copied()
        .chain([layout.scheme_off, layout.ptr_off])
        .map(|off| off + WORD)
        .max()
        .unwrap_or(CONTRACT_CONTEXT_BYTES);
    let mem_len = region_end.max(usize::try_from(last_word_end).unwrap_or(usize::MAX));
    let mut user_memory = vec![0u8; mem_len];

    put_word(&mut user_memory, layout.scheme_off, u64::from(SCHEME_LATTICE))?;
    put_word(&mut user_memory, layout.ptr_off, layout.region_off)?;
    for (off, value) in layout.field_offs.iter().zip(fields) {
        put_word(&mut user_memory, *off, *value)?;
    }

    let pk_end = region_off + public_key.len();
    let sig_end = pk_end + signature.len();
    user_memory[region_off..pk_end].copy_from_slice(&public_key);
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

/// The raw thirty two byte payload of a q1 contract address, the bytes the trusted context injects as
fn contract_id(contract: &str) -> Result<[u8; 32], String> {
    let payload = qtv_idfmt::parse_address(contract).map_err(|_| "the contract is not a q1 address")?;
    payload
        .as_slice()
        .try_into()
        .map_err(|_| "the contract address is not the canonical thirty two byte width".to_string())
}

/// Write a machine word big endian into scratch memory at a byte offset, the way the machine's MLoad
fn put_word(memory: &mut [u8], offset: u64, value: u64) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|_| "an argument offset is too large")?;
    let end = start.checked_add(WORD as usize).ok_or("an argument word overflows scratch")?;
    memory
        .get_mut(start..end)
        .ok_or("an argument word runs off the end of the argument memory")?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

// The wire encoders and decoders for contract reads. A binding calls these so no host builds a request
// body or reads a response field by hand.

/// The request body for get storage.
pub fn storage_body(address: &str) -> String {
    object(vec![("address", Json::str(address))]).render()
}

/// The request body for get events at a height.
pub fn events_body(height: u64) -> String {
    object(vec![("height", Json::Int(height))]).render()
}

/// One storage slot of a contract, its full thirty two byte key and the word it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlot {
    pub slot: [u8; 32],
    pub value: u64,
}

/// One event a block recorded, the contract that emitted it, its four byte interface selector, and its
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEvent {
    pub contract: String,
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

/// Parse a get storage response into its slots. Each slot key is sixty four hex characters and each
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

/// The word at a storage slot key among parsed slots, or zero when the slot is absent, the way the
pub fn storage_value(slots: &[StorageSlot], key: &[u8; 32]) -> u64 {
    slots
        .iter()
        .find(|slot| &slot.slot == key)
        .map(|slot| slot.value)
        .unwrap_or(0)
}

/// Parse a get events response into its events, each with the contract that emitted it, its selector,
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

/// The whole payload word of a single word event, big endian, so a `Bumped(u64)` event reads back the
pub fn event_word(data: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = data.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Counter contract the secured compiler emits, its bump entry signed by owner. The selector and
    // the argument layout are the ground truth from `quanta-cli emit`.
    const BUMP_SELECTOR: [u8; 4] = [0x6c, 0xad, 0x12, 0xfc];
    const BUMPED_SELECTOR: [u8; 4] = [0x6e, 0x82, 0x53, 0x1d];

    fn counter_layout() -> OrderLayout {
        // @caller 0, @contract 32, @time 64, order#scheme 72, order#ptr 80, order.step 88.
        OrderLayout::new(72, 80, vec![88])
    }

    #[test]
    fn the_signer_address_is_the_account_address_payload() {
        // The signer address the order binds to is the raw payload of the owner's own q1 address, so a
        // contract that stored `owner = deployer` binds the deployer's key.
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
        let order =
            build_signed_order_call(&contract, BUMP_SELECTOR, &layout, &[5], &seed, 0, 0).unwrap();

        // The scheme word carries the module lattice scheme, the pointer word carries the region
        // offset, and the field word carries the step, each big endian at the emit offset.
        assert_eq!(word_at(&order.user_memory, 72), u64::from(SCHEME_LATTICE));
        assert_eq!(word_at(&order.user_memory, 80), DEFAULT_REGION_OFFSET);
        assert_eq!(word_at(&order.user_memory, 88), 5);

        // The trusted context stays zero for the node to inject.
        assert!(order.user_memory[..CONTRACT_CONTEXT_BYTES as usize].iter().all(|&b| b == 0));

        // The call args are the selector then the argument memory.
        assert_eq!(&order.call_args[..4], &BUMP_SELECTOR);
        assert_eq!(&order.call_args[4..], &order.user_memory[..]);
    }

    #[test]
    fn the_verify_region_is_public_key_then_signature_then_message() {
        let seed = [9u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let order =
            build_signed_order_call(&contract, BUMP_SELECTOR, &counter_layout(), &[3], &seed, 0, 0)
                .unwrap();
        let base = DEFAULT_REGION_OFFSET as usize;
        let pk = order.public_key.len();
        let sig = order.signature.len();
        assert_eq!(&order.user_memory[base..base + pk], &order.public_key[..]);
        assert_eq!(&order.user_memory[base + pk..base + pk + sig], &order.signature[..]);
        assert_eq!(&order.user_memory[base + pk + sig..base + pk + sig + order.message.len()], &order.message[..]);
    }

    #[test]
    fn the_message_is_the_canonical_order_and_the_owner_signature_verifies() {
        let seed = [3u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let signer = order_signer(&seed, 0);
        let contract_id = super::contract_id(&contract).unwrap();
        let expected = canonical_order_message(&contract_id, BUMP_SELECTOR, &signer, 7, &[42]);
        let order =
            build_signed_order_call(&contract, BUMP_SELECTOR, &counter_layout(), &[42], &seed, 0, 7)
                .unwrap();
        assert_eq!(order.message, expected);
        assert_eq!(order.message.len(), 96, "tag 8, contract 32, selector 8, signer 32, nonce 8, one field 8");

        // The signature the client produced verifies over the message under the owner's public key, the
        // exact check the machine's verify opcode runs.
        assert!(ml_dsa::verify(
            order.public_key.as_slice().try_into().unwrap(),
            &order.message,
            order.signature.as_slice().try_into().unwrap(),
            &[],
        ));
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
        // The Counter layout expects one field; two is refused.
        assert!(build_signed_order_call(&contract, BUMP_SELECTOR, &counter_layout(), &[1, 2], &seed, 0, 0).is_err());
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
}
