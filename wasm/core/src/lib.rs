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

/// The raw signing boundary (REARCH R12 S4): sign `payload` in
/// `domain` with the operator key derived from the seed; writes the
/// 64-byte signature to `sig_out`.
///
/// # Safety
/// All pointers name readable/writable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_sign_raw(
    seed: *const u8,
    domain_ptr: *const u8,
    domain_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    sig_out: *mut u8,
) -> i32 {
    let seed = std::slice::from_raw_parts(seed, 32);
    let domain_bytes = std::slice::from_raw_parts(domain_ptr, domain_len);
    let payload = std::slice::from_raw_parts(payload_ptr, payload_len);
    let key = match operator_key(seed) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let domain = match std::str::from_utf8(domain_bytes) {
        Ok(text) => match domain_token(text) {
            Some(domain) => domain,
            None => return -2,
        },
        Err(_) => return -2,
    };
    let slot = match SignatureSlot::sign(&key, domain, payload) {
        Ok(slot) => slot,
        Err(_) => return -3,
    };
    let Some(signature) = slot.signature.as_deref() else {
        return -4;
    };
    std::ptr::copy_nonoverlapping(signature.as_ptr(), sig_out, signature.len());
    0
}

fn domain_token(text: &str) -> Option<SigningDomain> {
    match text {
        "tree-head" => Some(SigningDomain::TreeHead),
        "artifact-event" => Some(SigningDomain::ArtifactEvent),
        "profile" => Some(SigningDomain::Profile),
        "tree-head" => Some(SigningDomain::TreeHead),
        "notarization" => Some(SigningDomain::TreeHead),
        "s13-message" => Some(SigningDomain::S13Message),
        "interop-declaration" => Some(SigningDomain::InteropDeclaration),
        "hub-relay" => Some(SigningDomain::HubRelay),
        "segment-policy" => Some(SigningDomain::SegmentPolicy),
        "spine-root" => Some(SigningDomain::SpineRoot),
        _ => None,
    }
}

/// The issuer's mint boundary (REARCH R12 S4): `Passport::mint` from
/// the unidpp-cli crate — the same document the native issuer mints,
/// serialized with its own writer. Returns the passport's JSON
/// (pretty, trailing newline), or a negative code with the error in
/// `err_out` when the input rejects.
///
/// # Safety
/// All pointers name readable memory of the stated lengths; `err_out`
/// names 1024 writable bytes.
// The issuer's mint, THE SAME SOURCE the native issuer compiles
// (included by path — byte-exactness by construction, none of the
// cli crate's binary/tokio baggage on wasm).
#[path = "../../../../unidpp-cli/src/passport.rs"]
mod passport;

#[no_mangle]
pub unsafe extern "C" fn unidpp_mint_passport(
    id_ptr: *const u8,
    id_len: usize,
    granularity_ptr: *const u8,
    granularity_len: usize,
    capability_ptr: *const u8,
    capability_len: usize,
    passport_id_ptr: *const u8,
    passport_id_len: usize,
    valid_from_secs: i64,
    out_len_ptr: *mut usize,
    err_out: *mut u8,
) -> i32 {
    use passport::{MintOptions, Passport};
    let read_str = |ptr: *const u8, len: usize| -> String {
        if ptr.is_null() || len == 0 {
            return String::new();
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let id = read_str(id_ptr, id_len);
    let granularity = read_str(granularity_ptr, granularity_len);
    let capability = read_str(capability_ptr, capability_len);
    let passport_id = read_str(passport_id_ptr, passport_id_len);
    let write_err = |message: &str| -> i32 {
        let bytes = message.as_bytes();
        let len = bytes.len().min(1024);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), err_out, len);
        }
        -1
    };
    // wasm32 panics abort (no unwinding); the hook is the only way
    // the message escapes before the trap.
    static mut PANIC_MESSAGE: Option<String> = None;
    std::panic::set_hook(Box::new(|info| {
        let message = format!("{info}");
        unsafe {
            PANIC_MESSAGE = Some(message);
        }
    }));
    let minted = std::panic::catch_unwind(|| {
        Passport::mint_at(
            MintOptions {
                id,
                granularity: None,
                type_ref: None,
                capability,
                eo_id: None,
                resolver_uri: None,
                passport_id: if passport_id.is_empty() {
                    None
                } else {
                    Some(passport_id)
                },
                valid_from: Some(unidpp_model::time::Timestamp {
                    secs: valid_from_secs,
                    nanos: 0,
                }),
                valid_to: None,
            },
            unidpp_model::time::Timestamp {
                secs: valid_from_secs,
                nanos: 0,
            },
        )
        .and_then(|passport| passport.to_json())
    });
    let panic_message = unsafe { PANIC_MESSAGE.take() };
    let _ = std::panic::take_hook();
    let rendered = match minted {
        Ok(Ok(text)) => text,
        Ok(Err(message)) => return write_err(&format!("passport rejected: {message}")),
        Err(_) => {
            return write_err(&format!(
                "passport mint panicked: {}",
                panic_message.unwrap_or_else(|| "no message captured".to_string())
            ))
        }
    };
    let bytes = rendered.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err_out, 0);
    }
    // The document rides the same buffer contract as the key id: too
    // large for the error buffer, so the caller sizes it via the
    // length pointer.
    unsafe {
        *out_len_ptr = bytes.len();
    }
    if bytes.len() > 65536 {
        return write_err("the passport document exceeds the boundary budget");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err_out, bytes.len());
        *out_len_ptr = bytes.len();
    }
    0
}
