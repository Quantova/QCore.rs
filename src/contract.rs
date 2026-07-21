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

/// Marks deploy arguments as carrying deploy parameters after the container. The node's own tag.
const DEPLOY_PARAMS_TAG: &[u8; 8] = b"QDEPLOY1";

/// Closes the deploy parameter region. The compiler's own sentinel.
const GENESIS_PARAM_SENTINEL: &[u8; 8] = b"QGENSNTL";

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

/// A committed order field or call argument: a machine word or a full address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Word(u64),
    Address([u8; 32]),
}

impl FieldValue {
    fn bytes(&self) -> Vec<u8> {
        match self {
            FieldValue::Word(w) => w.to_be_bytes().to_vec(),
            FieldValue::Address(a) => a.to_vec(),
        }
    }

    fn width(&self) -> u64 {
        match self {
            FieldValue::Word(_) => WORD,
            FieldValue::Address(_) => 32,
        }
    }
}

/// An argument value and the scratch offset it is placed at. Order fields are listed in the message's
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldArg {
    pub offset: u64,
    pub value: FieldValue,
}

/// The canonical order message: the domain tag, the contract, the selector word, the signer, the
pub fn canonical_order_message_typed(
    contract_id: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[FieldValue],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSG_FIELDS_OFF);
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
        msg.extend_from_slice(&field.bytes());
    }
    msg
}

/// The word only case of [`canonical_order_message_typed`].
pub fn canonical_order_message(
    contract_id: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let typed: Vec<FieldValue> = fields.iter().copied().map(FieldValue::Word).collect();
    canonical_order_message_typed(contract_id, selector, signer, nonce, &typed)
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

/// The general form of [`build_signed_order_call`], whose order fields may be full addresses as well as
#[allow(clippy::too_many_arguments)]
pub fn build_typed_order_call(
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
    let contract_id = contract_id(contract)?;

    let seed = account_seed(owner_seed, SCHEME_LATTICE, owner_index);
    let (public_key, secret) = ml_dsa::keygen(&seed);
    debug_assert_eq!(
        public_key.len(),
        qtv_vm::abi::ML_DSA_PUBLIC_KEY_BYTES,
        "the derived public key length must be the machine's module lattice public key length"
    );

    let signer = signer_address(SCHEME_LATTICE, &public_key);
    let values: Vec<FieldValue> = fields.iter().map(|f| f.value.clone()).collect();
    let message = canonical_order_message_typed(&contract_id, selector, &signer, nonce, &values);

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

    let last_word_end = fields
        .iter()
        .map(|f| f.offset + f.value.width())
        .chain([scheme_off + WORD, ptr_off + WORD])
        .max()
        .unwrap_or(CONTRACT_CONTEXT_BYTES);
    let mem_len = region_end.max(usize::try_from(last_word_end).unwrap_or(usize::MAX));
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

/// A plain call's arguments: the selector then the argument memory, the context left for the node.
pub fn build_call_args(selector: [u8; 4], args: &[FieldArg]) -> Result<Vec<u8>, String> {
    let mem_len = args
        .iter()
        .map(|f| f.offset + f.value.width())
        .max()
        .unwrap_or(CONTRACT_CONTEXT_BYTES)
        .max(CONTRACT_CONTEXT_BYTES);
    let mut user_memory = vec![0u8; usize::try_from(mem_len).map_err(|_| "an argument offset is too large")?];
    for field in args {
        put_bytes(&mut user_memory, field.offset, &field.value.bytes())?;
    }
    let mut call_args = Vec::with_capacity(selector.len() + user_memory.len());
    call_args.extend_from_slice(&selector);
    call_args.extend_from_slice(&user_memory);
    Ok(call_args)
}

/// A deploy parameter value, matching the widths the compiler assigns.
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

/// Frame deploy arguments: the tag, the container length, the container, then the parameters closed by
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

/// Write a byte run into scratch memory at a byte offset.
fn put_bytes(memory: &mut [u8], offset: u64, bytes: &[u8]) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|_| "an argument offset is too large")?;
    let end = start.checked_add(bytes.len()).ok_or("an argument value overflows scratch")?;
    memory
        .get_mut(start..end)
        .ok_or("an argument value runs off the end of the argument memory")?
        .copy_from_slice(bytes);
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

    // The QAsset mint layout from `quanta-cli emit examples/QAsset.qs`: order.to at 72 as a full address,
    // order#scheme at 104, order#ptr at 112, order.amount at 120. The message commits order.amount then
    // order.to, the compiler's first appearance order.
    const MINT_SELECTOR: [u8; 4] = [0x3e, 0xcc, 0xb9, 0xbc];

    #[test]
    fn a_typed_order_binds_a_word_and_a_whole_address_field() {
        let seed = [4u8; crate::SEED_LEN];
        let contract = crate::contract_address(&crate::account_address(&seed, 0), 0).unwrap();
        let to = [0xABu8; 32];
        let fields = vec![
            FieldArg { offset: 120, value: FieldValue::Word(500) },
            FieldArg { offset: 72, value: FieldValue::Address(to) },
        ];
        let order = build_typed_order_call(&contract, MINT_SELECTOR, 104, 112, DEFAULT_REGION_OFFSET, &fields, &seed, 0, 0).unwrap();

        // The message is tag, contract, selector, signer, nonce, then the amount word and the whole
        // recipient address: eighty eight bytes of header plus one word plus one address.
        assert_eq!(order.message.len(), 88 + 8 + 32);
        assert_eq!(&order.message[88..96], &500u64.to_be_bytes());
        assert_eq!(&order.message[96..128], &to);

        // The amount word lands at its offset and the whole address at its offset, and the scheme and
        // pointer words carry the module lattice scheme and the region offset.
        assert_eq!(word_at(&order.user_memory, 120), 500);
        assert_eq!(&order.user_memory[72..104], &to);
        assert_eq!(word_at(&order.user_memory, 104), u64::from(SCHEME_LATTICE));
        assert_eq!(word_at(&order.user_memory, 112), DEFAULT_REGION_OFFSET);

        // The owner's signature verifies over the message, the exact check the machine's verify runs.
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
        let word = build_signed_order_call(&contract, BUMP_SELECTOR, &layout, &[7], &seed, 0, 3).unwrap();
        let typed = build_typed_order_call(
            &contract,
            BUMP_SELECTOR,
            layout.scheme_off,
            layout.ptr_off,
            layout.region_off,
            &[FieldArg { offset: 88, value: FieldValue::Word(7) }],
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
        // The QAsset transfer layout: to at 72 as a full address, amount at 104.
        let to = [0x2Cu8; 32];
        let selector = [0xb8, 0x4d, 0xbd, 0x2c];
        let args = build_call_args(
            selector,
            &[
                FieldArg { offset: 72, value: FieldValue::Address(to) },
                FieldArg { offset: 104, value: FieldValue::Word(200) },
            ],
        )
        .unwrap();
        assert_eq!(&args[..4], &selector);
        let mem = &args[4..];
        assert!(mem[..CONTRACT_CONTEXT_BYTES as usize].iter().all(|&b| b == 0), "context left for the node");
        assert_eq!(&mem[72..104], &to);
        assert_eq!(word_at(mem, 104), 200);
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
        // The frame: the tag, the container length, the container, then the parameter region.
        assert_eq!(&args[..8], DEPLOY_PARAMS_TAG);
        assert_eq!(u32::from_be_bytes(args[8..12].try_into().unwrap()) as usize, container.len());
        let cstart = 12;
        let cend = cstart + container.len();
        assert_eq!(&args[cstart..cend], &container[..]);
        // The parameter region: the owner address, the supply low then high word, then the sentinel.
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
        // Just the tag, the length, and the container, with an empty parameter region.
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
