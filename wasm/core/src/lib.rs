//! UniDPP's core algorithms on the wasm boundary (REARCH R12): the
//! digest path of the model crate, exported as a pure module with no
//! imports and no glue — every runtime (workerd, vitest, node)
//! instantiates it the same way, and the bytes stay the vector
//! corpus's bytes.

#[no_mangle]
pub extern "C" fn unidpp_alloc(len: usize) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr
}

/// # Safety
/// `ptr` must come from `unidpp_alloc` with the same `len`.
#[no_mangle]
pub unsafe extern "C" fn unidpp_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len));
}

/// The model crate's sha256 over one part, writing 32 bytes to `out`.
///
/// # Safety
/// `ptr` names `len` readable bytes; `out` names 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_sha256(ptr: *const u8, len: usize, out: *mut u8) {
    let data = std::slice::from_raw_parts(ptr, len);
    let digest = unidpp_model::sha256(&[data]);
    let bytes = digest.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32);
}

// ---------------------------------------------------------------------------
// The transparency-log boundary (REARCH R12 S3): the signed tree head's
// canonical bytes are built here — by the signatif crate itself — so the
// Worker's receipts verify byte-identically with the native estate. The
// operator key derives deterministically from the seed on every call;
// the secret never leaves the module. Pure exports, no glue: every
// runtime instantiates this module the same way.
// ---------------------------------------------------------------------------

use unidpp_model::time::Timestamp as ModelTimestamp;
use unidpp_model::Hash;
use unidpp_signatif::anchor::SignedTreeHead;
use unidpp_signatif::{KeyPair, SignatureSlot, SigningDomain, Suite};

fn operator_key(seed: &[u8]) -> Result<KeyPair, &'static str> {
    if seed.len() != 32 {
        return Err("the seed must be 32 bytes");
    }
    KeyPair::seeded(Suite::Ed25519, seed).map_err(|_| "key derivation failed")
}

fn sth_bytes(
    log_id: &[u8],
    tree_size: u64,
    secs: i64,
    nanos: u32,
    root: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if root.len() != 32 {
        return Err("the root must be 32 bytes");
    }

    let root = Hash::from_slice(root).ok_or("the root must be 32 bytes")?;
    let timestamp = ModelTimestamp { secs, nanos };
    let log_id = std::str::from_utf8(log_id).map_err(|_| "log_id must be utf-8")?;
    Ok(SignedTreeHead::canonical_bytes(
        log_id, tree_size, timestamp, &root,
    ))
}

/// The operator public key (32 bytes) for a seed.
///
/// # Safety
/// `seed` names 32 readable bytes; `out` names 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_head_public(seed: *const u8, out: *mut u8) -> i32 {
    let seed = std::slice::from_raw_parts(seed, 32);
    match operator_key(seed) {
        Ok(key) => {
            std::ptr::copy_nonoverlapping(key.public().as_bytes().as_ptr(), out, 32);
            0
        }
        Err(_) => -1,
    }
}

/// The operator key id (utf-8) for a seed, written to `out`; returns
/// its length, or -1.
///
/// # Safety
/// `seed` names 32 readable bytes; `out` names 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_head_key_id(seed: *const u8, out: *mut u8) -> i32 {
    let seed = std::slice::from_raw_parts(seed, 32);
    match operator_key(seed) {
        Ok(key) => {
            let id = key.key_id().as_str().as_bytes();
            if id.len() > 64 {
                return -1;
            }
            std::ptr::copy_nonoverlapping(id.as_ptr(), out, id.len());
            id.len() as i32
        }
        Err(_) => -1,
    }
}

/// Sign the tree head: writes the 64-byte ed25519 signature to
/// `sig_out`; returns 0 on success.
///
/// # Safety
/// All pointers name readable/writable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_sth_sign(
    seed: *const u8,
    log_id: *const u8,
    log_id_len: usize,
    tree_size: u64,
    secs: i64,
    nanos: u32,
    root: *const u8,
    sig_out: *mut u8,
) -> i32 {
    let seed = std::slice::from_raw_parts(seed, 32);
    let log_id = std::slice::from_raw_parts(log_id, log_id_len);
    let root = std::slice::from_raw_parts(root, 32);
    let key = match operator_key(seed) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let payload = match sth_bytes(log_id, tree_size, secs, nanos, root) {
        Ok(payload) => payload,
        Err(_) => return -2,
    };
    let slot = match SignatureSlot::sign(&key, SigningDomain::TreeHead, &payload) {
        Ok(slot) => slot,
        Err(_) => return -3,
    };
    let Some(signature) = slot.signature.as_deref() else {
        return -4;
    };
    std::ptr::copy_nonoverlapping(signature.as_ptr(), sig_out, signature.len());
    0
}

/// Verify a tree-head signature: 1 verifies, 0 refuses, -1 on shape
/// errors.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_sth_verify(
    public: *const u8,
    log_id: *const u8,
    log_id_len: usize,
    tree_size: u64,
    secs: i64,
    nanos: u32,
    root: *const u8,
    signature: *const u8,
) -> i32 {
    let public_bytes = std::slice::from_raw_parts(public, 32);
    let log_id = std::slice::from_raw_parts(log_id, log_id_len);
    let root = std::slice::from_raw_parts(root, 32);
    let signature = std::slice::from_raw_parts(signature, 64);
    let key = match unidpp_signatif::PublicKey::from_bytes_in(Suite::Ed25519, public_bytes) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let payload = match sth_bytes(log_id, tree_size, secs, nanos, root) {
        Ok(payload) => payload,
        Err(_) => return -1,
    };
    let slot = SignatureSlot {
        suite: Suite::Ed25519,
        key_id: unidpp_signatif::KeyId::of(&key),
        signature: Some(signature.to_vec()),
    };
    match slot.verify(SigningDomain::TreeHead, &payload, &key) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}
