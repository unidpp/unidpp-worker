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
    if seed.is_empty() {
        return Err("the seed material must not be empty");
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
        "master-list-witness" => Some(SigningDomain::MasterListWitness),
        "quorum" => Some(SigningDomain::Quorum),
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
    use unidpp_cli::passport::{MintOptions, Passport};
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

// ---------------------------------------------------------------------------
// The translation hub boundary (REARCH R12 S5): the relay core of the
// signatif crate itself — willingness both ways, the canonical relay
// payload, the HUB-RELAY signature. The hub carries no storage; the
// caller supplies the declarations and the evidence.
// ---------------------------------------------------------------------------

use unidpp_signatif::declaration::DeclarationSet;
use unidpp_signatif::transport::Hub;

fn declaration_set_from_json(text: &str) -> Result<DeclarationSet, &'static str> {
    let set: DeclarationSet =
        serde_json::from_str(text).map_err(|_| "the declarations do not deserialize")?;
    Ok(set)
}

/// Relay the evidence: willingness is checked both ways, the payload
/// is canonical and signed in the HUB-RELAY domain. Returns the
/// RelayedEvidence JSON, or a negative code (the refusal text rides
/// the note buffer).
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_hub_relay(
    hub_id_ptr: *const u8,
    hub_id_len: usize,
    evidence_ptr: *const u8,
    evidence_len: usize,
    from_ptr: *const u8,
    from_len: usize,
    to_ptr: *const u8,
    to_len: usize,
    data_class_ptr: *const u8,
    data_class_len: usize,
    seed_ptr: *const u8,
    declarations_ptr: *const u8,
    declarations_len: usize,
) -> i32 {
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let hub_id = read(hub_id_ptr, hub_id_len);
    let evidence = std::slice::from_raw_parts(evidence_ptr, evidence_len).to_vec();
    let from = read(from_ptr, from_len);
    let to = read(to_ptr, to_len);
    let data_class = read(data_class_ptr, data_class_len);
    let seed = std::slice::from_raw_parts(seed_ptr, 32);
    let declarations = read(declarations_ptr, declarations_len);
    let Ok(key) = operator_key(seed) else {
        return -1;
    };
    let Ok(set) = declaration_set_from_json(&declarations) else {
        return -2;
    };
    let hub = Hub { hub_id };
    match hub.relay(&evidence, &from, &to, &data_class, &set, &key) {
        Ok(relayed) => {
            // The signature slot's hex form rides the JSON the TS side
            // stores (the relayed evidence's own serde form).
            match serde_json::to_string(&relayed) {
                Ok(text) => {
                    unsafe {
                        DEBUG_TEXT = Some(text);
                    }
                    0
                }
                Err(_) => -3,
            }
        }
        Err(e) => {
            unsafe {
                DEBUG_TEXT = Some(format!("refused: {e}"));
            }
            -4
        }
    }
}

static mut DEBUG_TEXT: Option<String> = None;

/// The last note's bytes (a JSON document or a refusal), written to
/// `out`; returns the length. The caller's buffer must be at least
/// `unidpp_note_capacity` bytes.
///
/// # Safety
/// `out` names `unidpp_note_capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_note_take(out: *mut u8) -> i32 {
    match unsafe { DEBUG_TEXT.take() } {
        Some(text) => {
            let bytes = text.as_bytes();
            let len = bytes.len().min(NOTE_CAPACITY);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, len);
            len as i32
        }
        None => -1,
    }
}

/// The note buffer's capacity (the largest document the boundary
/// produces: a passport document or a view document).
#[no_mangle]
pub extern "C" fn unidpp_note_capacity() -> i32 {
    NOTE_CAPACITY as i32
}

const NOTE_CAPACITY: usize = 1_048_576;

/// Issue an interop declaration (REARCH R12 S5): signatif's own
/// `InteropDeclaration::issue` — the declarer signs the canonical
/// bytes in the INTEROP-DECLARATION domain. The postures ride as
/// JSON; the issued declaration (signature included) comes back in
/// the note buffer as JSON.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_declaration_issue(
    seed_ptr: *const u8,
    declarer_ptr: *const u8,
    declarer_len: usize,
    counterpart_ptr: *const u8,
    counterpart_len: usize,
    version: u64,
    postures_ptr: *const u8,
    postures_len: usize,
    valid_from_ptr: *const u8,
    valid_from_len: usize,
    valid_to_ptr: *const u8,
    valid_to_len: usize,
) -> i32 {
    use unidpp_signatif::declaration::{ClassPosture, InteropDeclaration};
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let seed = std::slice::from_raw_parts(seed_ptr, 32);
    let declarer = read(declarer_ptr, declarer_len);
    let counterpart = read(counterpart_ptr, counterpart_len);
    let postures_text = read(postures_ptr, postures_len);
    let valid_from = read(valid_from_ptr, valid_from_len);
    let valid_to = read(valid_to_ptr, valid_to_len);
    let Ok(key) = operator_key(seed) else {
        return -1;
    };
    let postures: Vec<ClassPosture> = match serde_json::from_str(&postures_text) {
        Ok(postures) => postures,
        Err(_) => return -2,
    };
    let issued = InteropDeclaration::issue(
        &declarer,
        &counterpart,
        version,
        postures,
        &valid_from,
        if valid_to.is_empty() {
            None
        } else {
            Some(valid_to.as_str())
        },
        &key,
    );
    match issued {
        Ok(declaration) => match serde_json::to_string(&declaration) {
            Ok(text) => {
                unsafe {
                    DEBUG_TEXT = Some(text);
                }
                0
            }
            Err(_) => -3,
        },
        Err(e) => {
            unsafe {
                DEBUG_TEXT = Some(format!("issue refused: {e}"));
            }
            -4
        }
    }
}

// ---------------------------------------------------------------------------
// The projector boundary (REARCH R12 S5-serve): the lens projection —
// THE SAME SOURCE the native projector compiles, included by path.
// The registry- and store-side IO stays on the TS side (the estate's
// own registry and issuer DOs are the sources); the boundary takes
// the passport document and the lens item, returns the view document.
// ---------------------------------------------------------------------------

// The projector's modules refer to each other as crate::aggregate,
// crate::lens, ... — the boundary module must carry those exact names
// so the included sources compile unchanged.
#[path = "../../../../unidpp-projector/src/aggregate.rs"]
pub mod aggregate;
#[path = "../../../../unidpp-projector/src/codelist.rs"]
pub mod codelist;
#[path = "../../../../unidpp-projector/src/fixtures.rs"]
pub mod fixtures;
#[path = "../../../../unidpp-projector/src/lens.rs"]
pub mod lens;
#[path = "../../../../unidpp-projector/src/primmel.rs"]
pub mod primmel;
#[path = "../../../../unidpp-projector/src/project.rs"]
pub mod project;
#[path = "../../../../unidpp-projector/src/twin.rs"]
pub mod twin;

// The gateway's render surface, THE SAME SOURCE the native gateway
// compiles. `crate::source` is the boundary's own carrier (the
// gateway's source.rs is a loopback HTTP client with no meaning on
// the edge); the passport and the profile layer ride the estate's
// issuer and registry DOs on the TS side.
#[path = "../../../../unidpp-gateway/src/canonical.rs"]
pub mod canonical;
#[path = "../../../../unidpp-gateway/src/en18222.rs"]
pub mod en18222;
pub mod source;
#[path = "../../../../unidpp-gateway/src/untp.rs"]
pub mod untp;
#[path = "../../../../unidpp-gateway/src/verdict.rs"]
pub mod verdict;

// The clause-15 mapping discipline (the three tiers): the same
// MappingItem the semantics crate compiles, included by path, so the
// workbench's canonical preview and the intake's validation read the
// same bytes the corpus pins.
#[path = "../../../../unidpp-core/crates/semantics/src/mapping.rs"]
pub mod semantics_mapping;

// The Tier-A packer (the QR-carrier codec) and the CLI's pack signing:
// the pack route on the edge mints the same carriers the native
// issuer serves. The crate-root names are the tier_a layout the
// path-included sources reference.
// The CLI's pack signing rides the included packfile (its
// unidpp_tier_a import resolves against the real crate dependency);
// the pack route on the edge mints the same carriers the native
// issuer serves.
#[path = "../../../../unidpp-cli/src/packfile.rs"]
pub mod packfile;

use lens::LensManifest;
use project::project;

/// Project a view: the passport JSON + the lens item JSON + the query
/// fields, the view document JSON returned through the note buffer.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_view_project(
    passport_ptr: *const u8,
    passport_len: usize,
    lens_ptr: *const u8,
    lens_len: usize,
    at_secs: i64,
    actor_ptr: *const u8,
    actor_len: usize,
) -> i32 {
    use unidpp_cli::passport::Passport;
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let passport_text = read(passport_ptr, passport_len);
    let lens_text = read(lens_ptr, lens_len);
    let actor = read(actor_ptr, actor_len);
    std::panic::set_hook(Box::new(|info| {
        let message = format!("{info}");
        unsafe {
            DEBUG_TEXT = Some(format!("projector panic: {message}"));
        }
    }));
    let minted = std::panic::catch_unwind(|| {
        let passport = Passport::from_json(&passport_text)
            .map_err(|e| format!("not a passport document: {e}"))?;
        let item: serde_json::Value = serde_json::from_str(&lens_text)
            .map_err(|e| format!("the lens item is not JSON: {e}"))?;
        let lens = LensManifest::from_item(&item).map_err(|e| format!("lens item: {e}"))?;
        let at = if at_secs > 0 {
            unidpp_model::time::Timestamp {
                secs: at_secs,
                nanos: 0,
            }
        } else {
            unidpp_model::time::Timestamp::now()
        };
        project(
            &passport,
            &lens,
            at,
            &actor,
            &Default::default(),
            &project::ProfileSource::fallback("registry", None),
            &primmel::PackageSet::empty(),
            &codelist::MappingSet::empty(),
            &aggregate::ChildDocuments::empty(),
            &aggregate::RollupSealer::off(),
        )
        .map_err(|e| format!("projection: {e}"))
        .and_then(|view| serde_json::to_string(&view).map_err(|e| e.to_string()))
    });
    let _ = std::panic::take_hook();
    let outcome = match minted {
        Ok(Ok(text)) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Ok(Err(message)) => {
            unsafe {
                DEBUG_TEXT = Some(format!("view refused: {message}"));
            }
            -1
        }
        Err(_) => {
            let message = unsafe { DEBUG_TEXT.take() }.unwrap_or_default();
            unsafe {
                DEBUG_TEXT = Some(format!(
                    "view panicked: {}",
                    if message.is_empty() {
                        "no message".into()
                    } else {
                        message
                    }
                ));
            }
            -2
        }
    };
    outcome
}

/// The built-in fixture lens (REARCH R12 S5-serve): the native
/// fixtures module's own lens, serialized — the registry fallback the
/// Worker serves when the registry lacks the profile item.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_fixture_lens(profile_ptr: *const u8, profile_len: usize) -> i32 {
    let profile =
        String::from_utf8_lossy(std::slice::from_raw_parts(profile_ptr, profile_len)).into_owned();
    let lens = fixtures::fixture_lens(&profile);
    match lens {
        Some(lens) => {
            // The registry-item view the from_item contract expects:
            // the manifest rides the item's manifest slot.
            let item = serde_json::json!({
                "identifier": profile,
                "item_class": "profile",
                "manifest": lens,
            });
            match serde_json::to_string(&item) {
                Ok(text) => {
                    unsafe {
                        DEBUG_TEXT = Some(text);
                    }
                    0
                }
                Err(_) => -3,
            }
        }
        None => -5,
    }
}

/// The built-in demo passport (the fixtures module's own), serialized
/// pretty — the store fallback the Worker serves when the issuer
/// lacks the passport.
///
/// # Safety
/// `out_len` names 4 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_fixture_passport() -> i32 {
    match serde_json::to_string(&fixtures::demo_passport()) {
        Ok(text) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Err(_) => -3,
    }
}

/// Render one passport in a foreign protocol shape: the protocol
/// token selects the renderer ("en18222" | "untp"), the passport and
/// the profile layer ride the estate's DOs as JSON, and the caller
/// supplies the clock (SystemTime aborts on wasm32-unknown-unknown).
/// The rendered document returns through the note buffer.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_render(
    protocol_ptr: *const u8,
    protocol_len: usize,
    passport_ptr: *const u8,
    passport_len: usize,
    profiles_ptr: *const u8,
    profiles_len: usize,
    representation_ptr: *const u8,
    representation_len: usize,
    freshness_ptr: *const u8,
    freshness_len: usize,
    origin_ptr: *const u8,
    origin_len: usize,
    now_secs: i64,
) -> i32 {
    use unidpp_cli::passport::Passport;
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let protocol = read(protocol_ptr, protocol_len);
    let passport_text = read(passport_ptr, passport_len);
    let profiles_text = read(profiles_ptr, profiles_len);
    let representation = read(representation_ptr, representation_len);
    let freshness = read(freshness_ptr, freshness_len);
    let origin = read(origin_ptr, origin_len);
    std::panic::set_hook(Box::new(|info| {
        let message = format!("{info}");
        unsafe {
            DEBUG_TEXT = Some(format!("render panic: {message}"));
        }
    }));
    let rendered = std::panic::catch_unwind(move || {
        let passport = Passport::from_json(&passport_text)
            .map_err(|e| format!("not a passport document: {e}"))?;
        let profile_values: Vec<serde_json::Value> = serde_json::from_str(&profiles_text)
            .map_err(|e| format!("the profile layer is not a JSON array: {e}"))?;
        let profiles: Vec<source::ProfileRef> = profile_values
            .iter()
            .map(|value| {
                Ok(source::ProfileRef {
                    id: value
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or("the profile ref lacks `id`")?
                        .to_string(),
                    version: value
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or("the profile ref lacks `version`")?
                        .to_string(),
                    effective_from: match value.get("effective_from") {
                        Some(v) if !v.is_null() => {
                            let text = v
                                .as_str()
                                .ok_or("the profile effective_from is not a timestamp")?;
                            Some(unidpp_model::Timestamp::parse(text).map_err(|e| e.to_string())?)
                        }
                        _ => None,
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let gateway_passport = source::GatewayPassport {
            document: passport,
            profiles,
            origin: match origin.as_str() {
                "fixture" => source::Origin::Fixture,
                _ => source::Origin::Issuer,
            },
            anchors: std::collections::HashMap::new(),
        };
        let at = if now_secs > 0 {
            unidpp_model::Timestamp {
                secs: now_secs,
                nanos: 0,
            }
        } else {
            unidpp_model::Timestamp::now()
        };
        match protocol.as_str() {
            "en18222" => {
                let representation = en18222::Representation::parse(if representation.is_empty() {
                    None
                } else {
                    Some(&representation)
                })
                .map_err(|e| e)?;
                let document = en18222::render(&gateway_passport, representation, at);
                serde_json::to_string(&document).map_err(|e| e.to_string())
            }
            "untp" => {
                let required = if freshness.is_empty() {
                    None
                } else {
                    Some(freshness.as_str())
                };
                Ok(untp::render_triad(&gateway_passport, at, required).to_string())
            }
            other => Err(format!(
                "unknown protocol `{other}` (expected en18222|untp)"
            )),
        }
    });
    let _ = std::panic::take_hook();
    let outcome = match rendered {
        Ok(Ok(text)) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Ok(Err(message)) => {
            unsafe {
                DEBUG_TEXT = Some(format!("render refused: {message}"));
            }
            -1
        }
        Err(_) => {
            let message = unsafe { DEBUG_TEXT.take() }.unwrap_or_default();
            unsafe {
                DEBUG_TEXT = Some(format!(
                    "render panicked: {}",
                    if message.is_empty() {
                        "no message".into()
                    } else {
                        message
                    }
                ));
            }
            -2
        }
    };
    outcome
}

/// Validate a clause-15 mapping item and return its canonical form:
/// the item JSON in, `{canonical_hex, digest_hex}` out through the
/// note buffer; a negative code with the parse error in the note.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_mapping_validate(item_ptr: *const u8, item_len: usize) -> i32 {
    let text = String::from_utf8_lossy(std::slice::from_raw_parts(item_ptr, item_len)).into_owned();
    let parsed: Result<semantics_mapping::MappingItem, _> = serde_json::from_str(&text);
    match parsed {
        Ok(item) => {
            let hex =
                |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
            let document = serde_json::json!({
                "canonical_hex": hex(&item.canonical_bytes()),
                "digest_hex": hex(&item.digest()),
            });
            match serde_json::to_string(&document) {
                Ok(text) => {
                    unsafe {
                        DEBUG_TEXT = Some(text);
                    }
                    0
                }
                Err(_) => -3,
            }
        }
        Err(e) => {
            unsafe {
                DEBUG_TEXT = Some(format!("the mapping item does not parse: {e}"));
            }
            -1
        }
    }
}

/// Compose two mapping items into a chain (the clause-15 composition:
/// the first's target must be the second's source, a tier-3 hop
/// refuses, the policy cap holds) and return the chain JSON —
/// endpoints, hops, accumulated residual and intersected scope —
/// through the note buffer.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_mapping_compose(
    first_ptr: *const u8,
    first_len: usize,
    second_ptr: *const u8,
    second_len: usize,
    cap: u64,
) -> i32 {
    let first_text =
        String::from_utf8_lossy(std::slice::from_raw_parts(first_ptr, first_len)).into_owned();
    let second_text =
        String::from_utf8_lossy(std::slice::from_raw_parts(second_ptr, second_len)).into_owned();
    let parse = |text: &str| -> Result<semantics_mapping::MappingItem, String> {
        serde_json::from_str(text).map_err(|e| format!("a mapping item does not parse: {e}"))
    };
    let outcome = (|| -> Result<serde_json::Value, String> {
        let first = parse(&first_text)?;
        let second = parse(&second_text)?;
        let chain = semantics_mapping::MappingChain::single(first)
            .map_err(|e| e.to_string())?
            .then(second, cap as usize)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(&chain).map_err(|e| e.to_string())
    })();
    match outcome {
        Ok(chain) => match serde_json::to_string(&chain) {
            Ok(text) => {
                unsafe {
                    DEBUG_TEXT = Some(text);
                }
                0
            }
            Err(_) => -3,
        },
        Err(message) => {
            unsafe {
                DEBUG_TEXT = Some(message);
            }
            -1
        }
    }
}

/// Mint the Tier-A carrier for one passport: the passport JSON + the
/// signing seed + the suite token ("ecdsa-p256", or a comma-separated
/// co-signature list), the carrier document JSON through the note
/// buffer — the same shape the native issuer serves (pack, bytes,
/// projected, qr_version, ec, margin, signature, signatures, anchor,
/// anchors). The clock rides the caller (SystemTime aborts here); the
/// payload's stamps come from the passport's own log.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_mint_pack(
    passport_ptr: *const u8,
    passport_len: usize,
    seed_ptr: *const u8,
    seed_len: usize,
    suites_ptr: *const u8,
    suites_len: usize,
) -> i32 {
    use unidpp_cli::passport::Passport;
    use unidpp_signatif::Suite;
    use unidpp_tier_a::{TierAPacker, TierAPayload};
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let passport_text = read(passport_ptr, passport_len);
    // The seed rides as raw bytes (a digest — not UTF-8); only the
    // text arguments go through the lossy read.
    let seed_bytes = std::slice::from_raw_parts(seed_ptr, seed_len).to_vec();
    let suites_text = read(suites_ptr, suites_len);
    std::panic::set_hook(Box::new(|info| {
        let message = format!("{info}");
        unsafe {
            DEBUG_TEXT = Some(format!("pack panic: {message}"));
        }
    }));
    let minted = std::panic::catch_unwind(move || {
        let passport = Passport::from_json(&passport_text)
            .map_err(|e| format!("not a passport document: {e}"))?;
        if seed_bytes.is_empty() {
            return Err("the signing seed must not be empty".to_string());
        }
        let suites: Vec<Suite> = if suites_text.is_empty() {
            vec![Suite::EcdsaP256]
        } else {
            suites_text
                .split(',')
                .map(|t| match t.trim() {
                    "ecdsa-p256" => Some(Suite::EcdsaP256),
                    "sm2" => Some(Suite::Sm2),
                    "ml-dsa-44" => Some(Suite::MlDsa44),
                    "ml-dsa-65" => Some(Suite::MlDsa65),
                    "ml-dsa-87" => Some(Suite::MlDsa87),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    "unknown suite token (expected ecdsa-p256 | sm2 | ml-dsa-*)".to_string()
                })?
        };
        let payload = TierAPayload::from_log(
            &passport.log,
            passport.product_id.clone(),
            &passport.resolver_uri,
            &passport.eo_id,
            passport.validity,
            Vec::new(),
        );
        let (signed, anchors) = packfile::sign_pack_suites(&payload, &seed_bytes, &suites)
            .map_err(|e| format!("pack signing: {e}"))?;
        let packer = TierAPacker::new(unidpp_tier_a::qr::EcLevel::M, 40);
        let packed = packer.pack(&signed).map_err(|e| e.to_string())?;
        let signature_entries: Vec<serde_json::Value> = anchors
            .iter()
            .map(|(public, key_id)| {
                serde_json::json!({
                    "suite": public.suite().to_string(),
                    "key_id": key_id.to_string(),
                    "anchor": hex_of_upper(public.as_bytes()),
                })
            })
            .collect();
        let anchors_map: serde_json::Map<String, serde_json::Value> = anchors
            .iter()
            .map(|(public, key_id)| {
                (
                    public.suite().to_string(),
                    serde_json::Value::String(hex_of_upper(public.as_bytes())),
                )
            })
            .collect();
        let document = serde_json::json!({
            "passport_id": passport.passport_id.as_str(),
            "encoding": "hex",
            "pack": hex_of_upper(packed.as_slice()),
            "bytes": packed.used,
            "projected": packed.projected,
            "qr_version": packed.version,
            "ec": "m",
            "margin": packed.margin(),
            "signature": signature_entries.first().cloned().unwrap_or(serde_json::Value::Null),
            "signatures": signature_entries,
            "anchor": signature_entries
                .first()
                .and_then(|s| s.get("anchor").cloned())
                .unwrap_or(serde_json::Value::Null),
            "anchors": anchors_map,
        });
        serde_json::to_string(&document).map_err(|e| e.to_string())
    });
    let _ = std::panic::take_hook();
    let outcome = match minted {
        Ok(Ok(text)) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Ok(Err(message)) => {
            unsafe {
                DEBUG_TEXT = Some(format!("pack refused: {message}"));
            }
            -1
        }
        Err(_) => {
            let message = unsafe { DEBUG_TEXT.take() }.unwrap_or_default();
            unsafe {
                DEBUG_TEXT = Some(format!(
                    "pack panicked: {}",
                    if message.is_empty() {
                        "no message".into()
                    } else {
                        message
                    }
                ));
            }
            -2
        }
    };
    outcome
}

fn hex_of_upper(bytes: &[u8]) -> String {
    // The CLI's hex_encode alphabet: lowercase (the corpus's case).
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The S13 federation boundary (the adoption audit's cross-border gap):
// the seam's policy evaluation stays the s13 crate's own `evaluate`
// (the four outcomes, the stated denial, the governing-policy citation),
// and the trust layer's signature verification rides the signatif
// crate's own slot verify — the same bytes the native estate signs.
// ---------------------------------------------------------------------------

/// Evaluate one S13 request under one grid policy: the policy and the
/// request ride as JSON (the grid's PolicyObject serde form), the
/// response JSON (digest binding, outcome, governing policy citation)
/// returns through the note buffer.
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_s13_evaluate(
    policy_ptr: *const u8,
    policy_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    custodian_ptr: *const u8,
    custodian_len: usize,
) -> i32 {
    use unidpp_grid::PolicyObject;
    use unidpp_s13::{S13Request, S13Response};
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let outcome = (|| -> Result<String, String> {
        let policy: PolicyObject = serde_json::from_str(&read(policy_ptr, policy_len))
            .map_err(|e| format!("the policy does not parse: {e}"))?;
        let request: S13Request = serde_json::from_str(&read(request_ptr, request_len))
            .map_err(|e| format!("the request does not parse: {e}"))?;
        let response =
            S13Response::evaluate(&request, &policy, &read(custodian_ptr, custodian_len));
        serde_json::to_string(&response).map_err(|e| e.to_string())
    })();
    match outcome {
        Ok(text) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Err(message) => {
            unsafe {
                DEBUG_TEXT = Some(format!("s13 refused: {message}"));
            }
            -1
        }
    }
}

/// Verify a domain-framed signature under one public key — the
/// general verify the S13 trust layer needs (the requester's, the
/// custodian's, the authority's slots all ride the S13-MESSAGE
/// domain over canonical bytes). 1 verifies, 0 refuses, -1 on shape
/// errors (an unknown domain or suite token).
///
/// # Safety
/// All pointers name readable memory of the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn unidpp_verify_raw(
    domain_ptr: *const u8,
    domain_len: usize,
    suite_ptr: *const u8,
    suite_len: usize,
    public_ptr: *const u8,
    public_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let domain = match domain_token(&read(domain_ptr, domain_len)) {
        Some(domain) => domain,
        None => return -1,
    };
    let suite = match read(suite_ptr, suite_len).as_str() {
        "ed25519" => Suite::Ed25519,
        "ecdsa-p256" => Suite::EcdsaP256,
        _ => return -1,
    };
    let public_bytes = std::slice::from_raw_parts(public_ptr, public_len);
    let key = match unidpp_signatif::PublicKey::from_bytes_in(suite, public_bytes) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let payload = std::slice::from_raw_parts(payload_ptr, payload_len);
    let slot = SignatureSlot {
        suite,
        key_id: unidpp_signatif::KeyId::of(&key),
        signature: Some(std::slice::from_raw_parts(sig_ptr, sig_len).to_vec()),
    };
    match slot.verify(domain, payload, &key) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// The S13 dossier boundary (SI-9/10/11): the verification route's and the
// coverage report's canonical forms — the same encoders the corpus's
// fixtures pin and the CLI's F2 conformance reads — plus the composition
// law. Pure functions of their JSON inputs; the canonical bytes and the
// digest ride the note buffer.
// ---------------------------------------------------------------------------

fn canonical_note(value: serde_json::Value) -> i32 {
    match serde_json::to_string(&value) {
        Ok(text) => {
            unsafe {
                DEBUG_TEXT = Some(text);
            }
            0
        }
        Err(_) => -3,
    }
}

fn parse_error(prefix: &str, message: String) -> i32 {
    unsafe {
        DEBUG_TEXT = Some(format!("{prefix}: {message}"));
    }
    -1
}

// ---------------------------------------------------------------------------
// The event-seal boundary: the native issuer's full typed intake —
// type token, payload, the transition checks, the hash-chained append
// into the passport's EventLog, and the ArtifactEvent signature under
// the deployment's event key. The same unidpp-event intake layer the
// native HTTP body runs, so the constructed events, their bytes and
// their refusals agree with the native estate.
// ---------------------------------------------------------------------------

/// The intake outcome written through the note buffer: on success rc 0
/// with the appended log, the signature record, the head and the
/// status/safety/trust render; on refusal rc negative with
/// `{"error": ..., "status": ...}` — the native texts verbatim.
///
/// # Safety
/// `request_ptr`/`state_ptr` name readable JSON of the stated lengths;
/// `seed` names 32 readable bytes; `out` names `out_cap` writable
/// bytes; `out_len` names one writable u32.
#[no_mangle]
pub unsafe extern "C" fn unidpp_event_seal(
    request_ptr: *const u8,
    request_len: usize,
    state_ptr: *const u8,
    state_len: usize,
    seed_ptr: *const u8,
    seed_len: usize,
    out_len: *mut u32,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    use unidpp_cli::passport::EventSignature;
    use unidpp_event::intake::{default_payload, payload_from_data};
    use unidpp_event::{EventPayload, EventType, TypedEvent};
    use unidpp_model::time::Timestamp as ModelTimestamp;
    use unidpp_model::TrustMarker;
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let refuse = |status: u16, message: String| -> i32 {
        unsafe {
            DEBUG_TEXT = Some(serde_json::json!({"error": message, "status": status}).to_string());
        }
        -1
    };
    let request: serde_json::Value = match serde_json::from_str(&read(request_ptr, request_len)) {
        Ok(v) => v,
        Err(e) => return refuse(400, format!("invalid JSON body: {e}")),
    };
    let state: serde_json::Value = match serde_json::from_str(&read(state_ptr, state_len)) {
        Ok(v) => v,
        Err(e) => return refuse(400, format!("invalid state JSON: {e}")),
    };
    let outcome = (|| -> Result<serde_json::Value, (u16, String)> {
        let Some(type_token) = request.get("type").and_then(|v| v.as_str()) else {
            return Err((400, "`type` is required".into()));
        };
        let event_type = EventType::parse_token(type_token)
            .map_err(|e| (400u16, format!("`type` `{type_token}`: {e}")))?;
        let payload = match request.get("data").or_else(|| request.get("payload")) {
            None | Some(serde_json::Value::Null) => {
                default_payload(event_type).ok_or_else(|| {
                    (
                        400u16,
                        format!(
                            "`data` is required for {event_type} (the payload has operator-supplied fields)"
                        ),
                    )
                })?
            }
            Some(data) => payload_from_data(event_type, data)
                .map_err(|e| (400u16, format!("`data`: {e}")))?,
        };
        let occurred_at = match request.get("at") {
            None | Some(serde_json::Value::Null) => {
                let Some(now) = state.get("now").and_then(|v| v.as_i64()) else {
                    return Err((
                        400,
                        "the state carries no `now` (the boundary carries no wall clock)".into(),
                    ));
                };
                ModelTimestamp::from_secs(now)
            }
            Some(serde_json::Value::String(s)) => {
                ModelTimestamp::parse(s).map_err(|e| (400u16, format!("`at`: {e}")))?
            }
            Some(_) => return Err((400, "`at` must be an RFC 3339 string".into())),
        };
        let sign = match request.get("sign") {
            None | Some(serde_json::Value::Null) => true,
            Some(v) => v
                .as_bool()
                .ok_or((400, "`sign` must be a boolean".into()))?,
        };
        let trust = if sign {
            TrustMarker::Attested
        } else {
            TrustMarker::Unsigned
        };
        let mut log: unidpp_event::EventLog =
            serde_json::from_value(state.get("log").cloned().unwrap_or(serde_json::Value::Null))
                .map_err(|e| (400u16, format!("the state's `log` does not parse: {e}")))?;
        let eo_id = state
            .get("eo_id")
            .and_then(|v| v.as_str())
            .ok_or((400, "the state carries no `eo_id`".into()))?
            .to_string();
        let seq = log.len() as u64;
        let actor_id = request
            .get("actor")
            .and_then(|v| v.as_str())
            .unwrap_or(&eo_id)
            .to_string();
        let actor_role = request
            .get("actor_role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| event_type.appender_role().to_string());
        let typed = TypedEvent::new(
            seq,
            occurred_at,
            &actor_role,
            &actor_id,
            event_type,
            payload.clone(),
            trust,
        )
        .map_err(|e| match e {
            unidpp_event::EventError::IllegalTransition { from, to } => (
                409u16,
                format!("illegal status transition {from} -> {to} (I6)"),
            ),
            other => (400u16, format!("event rejected: {other}")),
        })?;
        // The log's own transition guard (the store's intake check):
        // a status change must leave the log's current status.
        if let EventPayload::StatusChange { from, to, .. } = &payload {
            let current = log.current_status();
            if *from != current {
                return Err((
                    409u16,
                    format!(
                        "illegal status transition {from} -> {to}: the log's current status is {current} (I6)"
                    ),
                ));
            }
        }
        let body = typed
            .canonical_body()
            .map_err(|e| (400u16, format!("canonical body: {e}")))?;
        let signature = if sign {
            let seed_bytes = std::slice::from_raw_parts(seed_ptr, seed_len);
            let key = operator_key(seed_bytes).map_err(|e| (400u16, e.to_string()))?;
            let slot = SignatureSlot::sign(&key, SigningDomain::ArtifactEvent, &body)
                .map_err(|e| (400u16, format!("event signing failed: {e}")))?;
            Some(EventSignature {
                seq,
                suite: slot.suite.to_string(),
                key_id: slot.key_id.to_string(),
                signature: hex_lower(slot.signature.as_deref().unwrap_or(&[])),
            })
        } else {
            None
        };
        let head = log
            .append(typed, None, None)
            .map_err(|e| (400u16, format!("event rejected: {e}")))?;
        Ok(serde_json::json!({
            "log": log,
            "signature": signature,
            "head": hex_lower(head.as_bytes()),
            "seq": seq,
            "event_type": event_type,
            "occurred_at": occurred_at.to_string(),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "trust": trust,
            "status": log.current_status(),
            "safety": log.safety_flag(),
        }))
    })();
    match outcome {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(text) => {
                let bytes = text.as_bytes();
                if bytes.len() > out_cap {
                    return refuse(500, "the seal output exceeds the buffer".into());
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                unsafe {
                    out_len.write(bytes.len() as u32);
                }
                0
            }
            Err(_) => -2,
        },
        Err((status, message)) => {
            let text = serde_json::json!({"error": message, "status": status}).to_string();
            let bytes = text.as_bytes();
            if bytes.len() > out_cap {
                return -2;
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            unsafe {
                out_len.write(bytes.len() as u32);
            }
            -1
        }
    }
}

/// The canonical body of a stored typed event (the bytes an
/// ArtifactEvent signature covers) — the verdict audit's re-derivation
/// over the sealed entry's own JSON. The body rides the note buffer.
///
/// # Safety
/// `ptr` names `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_event_body(ptr: *const u8, len: usize) -> i32 {
    use unidpp_event::TypedEvent;
    let text = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned();
    let outcome = (|| -> Result<Vec<u8>, String> {
        let event: TypedEvent = serde_json::from_str(&text)
            .map_err(|e| format!("the sealed event does not parse: {e}"))?;
        event.canonical_body().map_err(|e| e.to_string())
    })();
    match outcome {
        Ok(body) => {
            unsafe {
                DEBUG_TEXT = Some(hex_lower(&body));
            }
            0
        }
        Err(message) => {
            unsafe {
                DEBUG_TEXT = Some(message);
            }
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// The verdict-leg boundary: the native issuer's two verdict legs run
// here — the log verdict through the verdict crate's builder and the
// Tier-A carrier leg through mint-then-verify — so the edge's graded
// verdicts carry the native shapes and the native verification, not a
// mirror of them.
// ---------------------------------------------------------------------------

/// The log verdict leg: `VerdictBuilder` over the passport's log at
/// the query instant, answering current-state, third-party attested
/// when signatures exist, anchored at the log head. The verdict rides
/// the out buffer as JSON.
///
/// # Safety
/// `log_ptr` names `log_len` readable JSON; `out` names `out_cap`
/// writable bytes; `out_len` names one writable u32.
#[no_mangle]
pub unsafe extern "C" fn unidpp_log_verdict(
    log_ptr: *const u8,
    log_len: usize,
    now_secs: i64,
    with_signatures: i32,
    out_len: *mut u32,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    use unidpp_event::EventLog;
    use unidpp_verdict::{Reading, VerdictBuilder};
    let text = String::from_utf8_lossy(std::slice::from_raw_parts(log_ptr, log_len)).into_owned();
    let outcome = (|| -> Result<serde_json::Value, String> {
        let log: EventLog = serde_json::from_str(&text)
            .map_err(|e| format!("the log does not parse: {e}"))?;
        let now = ModelTimestamp::from_secs(now_secs);
        let mut builder = VerdictBuilder::new(&log, now)
            .answering(Reading::CurrentState)
            .attested_by_third_party(with_signatures != 0);
        if let Some(head) = log.head() {
            builder = builder.with_anchor(head);
        }
        serde_json::to_value(builder.build()).map_err(|e| e.to_string())
    })();
    match outcome {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(ser) => {
                let bytes = ser.as_bytes();
                if bytes.len() > out_cap {
                    return -2;
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                unsafe {
                    out_len.write(bytes.len() as u32);
                }
                0
            }
            Err(_) => -2,
        },
        Err(message) => {
            unsafe {
                DEBUG_TEXT = Some(message);
            }
            -1
        }
    }
}

/// The Tier-A verdict leg: mint the carrier over the passport's log
/// (the pipeline /pack rides), verify it under the seeded pack
/// anchors, and render the graded outcome — the native issuer's leg
/// verbatim, verification included. The leg rides the out buffer as
/// JSON; the pack budget failure renders as the native 413-class
/// error (rc -1, the message in the note).
///
/// # Safety
/// All pointers name readable memory of the stated lengths; `out`
/// names `out_cap` writable bytes; `out_len` names one writable u32.
#[no_mangle]
pub unsafe extern "C" fn unidpp_tier_a_leg(
    document_ptr: *const u8,
    document_len: usize,
    seed_ptr: *const u8,
    seed_len: usize,
    suites_ptr: *const u8,
    suites_len: usize,
    now_secs: i64,
    max_age: i64,
    out_len: *mut u32,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    use unidpp_cli::commands::verify::verify_pack_with_anchors;
    use unidpp_cli::packfile::{sign_pack_suites, DEFAULT_BUDGET};
    use unidpp_cli::passport::Passport;
    use unidpp_signatif::Suite;
    use unidpp_tier_a::{TierAPacker, TierAPayload};
    let read = |ptr: *const u8, len: usize| -> String {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
    };
    let document_text = read(document_ptr, document_len);
    let seed_bytes = std::slice::from_raw_parts(seed_ptr, seed_len);
    let suites_text = read(suites_ptr, suites_len);
    let outcome = (|| -> Result<serde_json::Value, String> {
        let passport = Passport::from_json(&document_text)
            .map_err(|e| format!("not a passport document: {e}"))?;
        let suites: Vec<Suite> = if suites_text.is_empty() {
            vec![Suite::EcdsaP256]
        } else {
            suites_text
                .split(',')
                .map(|t| match t.trim() {
                    "ecdsa-p256" => Some(Suite::EcdsaP256),
                    "sm2" => Some(Suite::Sm2),
                    "ml-dsa-44" => Some(Suite::MlDsa44),
                    "ml-dsa-65" => Some(Suite::MlDsa65),
                    "ml-dsa-87" => Some(Suite::MlDsa87),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    "unknown suite token (expected ecdsa-p256 | sm2 | ml-dsa-*)".to_string()
                })?
        };
        let payload = TierAPayload::from_log(
            &passport.log,
            passport.product_id.clone(),
            &passport.resolver_uri,
            &passport.eo_id,
            passport.validity,
            Vec::new(),
        );
        let (signed, minted) = sign_pack_suites(&payload, seed_bytes, &suites)
            .map_err(|e| format!("pack signing: {e}"))?;
        let packer = TierAPacker::new(DEFAULT_BUDGET.0, DEFAULT_BUDGET.1);
        let packed = packer.pack(&signed).map_err(|e| e.to_string())?;
        let anchors: Vec<unidpp_signatif::keyring::PublicKey> =
            minted.iter().map(|(public, _)| *public).collect();
        let now = ModelTimestamp::from_secs(now_secs);
        let outcome = verify_pack_with_anchors(packed.as_slice(), &anchors, now, max_age);
        let summary = outcome.payload.as_ref().map(|p| {
            serde_json::json!({
                "status": p.status,
                "safety": p.safety,
                "as_of": p.as_of,
                "log_head": p.log_head.map(|h| h.hex()),
                "signatures": p.signatures.len(),
            })
        });
        Ok(serde_json::json!({
            "grade": outcome.grade.token(),
            "exit_code": outcome.grade.exit_code(),
            "reading_answered": outcome.reading_answered,
            "findings": outcome.findings,
            "readings": outcome.readings,
            "coverage": outcome.coverage,
            "freshness": outcome.freshness.map(|f| f.label()),
            "trust_marker": outcome.trust_marker.map(|t| t.as_str()),
            "carrier": {
                "bytes": packed.used,
                "projected": packed.projected,
                "qr_version": packed.version,
            },
            "payload": summary,
            "signature": {
                "suite": suites.first().copied().unwrap_or(Suite::EcdsaP256).to_string(),
                "key_id": minted
                    .first()
                    .map(|(_, k)| k.to_string())
                    .unwrap_or_default(),
            },
            "signatures": minted
                .iter()
                .map(|(public, key_id)| {
                    serde_json::json!({
                        "suite": public.suite().to_string(),
                        "key_id": key_id.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        }))
    })();
    match outcome {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(text) => {
                let bytes = text.as_bytes();
                if bytes.len() > out_cap {
                    return -2;
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                unsafe {
                    out_len.write(bytes.len() as u32);
                }
                0
            }
            Err(_) => -2,
        },
        Err(message) => {
            unsafe {
                DEBUG_TEXT = Some(message);
            }
            -1
        }
    }
}


fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The identity of a seeded signing key: the suite's key pair derived
/// from the seed material (the native keyring's derivation — the
/// material is the label bytes, any length), rendered as
/// `{suite, key_id, public}` through the note buffer.
///
/// # Safety
/// `seed_ptr` names `seed_len` readable bytes; `suite_ptr` names
/// `suite_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_key_identity(
    seed_ptr: *const u8,
    seed_len: usize,
    suite_ptr: *const u8,
    suite_len: usize,
) -> i32 {
    let seed = std::slice::from_raw_parts(seed_ptr, seed_len);
    let suite_text =
        String::from_utf8_lossy(std::slice::from_raw_parts(suite_ptr, suite_len)).into_owned();
    let suite = match suite_text.as_str() {
        "ed25519" => Suite::Ed25519,
        "ecdsa-p256" => Suite::EcdsaP256,
        _ => return -1,
    };
    let key = match KeyPair::seeded(suite, seed) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    unsafe {
        DEBUG_TEXT = Some(
            serde_json::json!({
                "suite": key.suite().to_string(),
                "key_id": key.key_id().as_str(),
                "public": hex_lower(key.public().as_bytes()),
            })
            .to_string(),
        );
    }
    0
}

/// Sign `payload` in `domain` with the suite's key pair derived from
/// the seed material (any length — the native keyring's label
/// convention); writes the signature to `sig_out` and returns its
/// byte length, negative on a shape error.
///
/// # Safety
/// All pointers name readable memory of the stated lengths; `sig_out`
/// names `sig_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_sign_suite(
    seed_ptr: *const u8,
    seed_len: usize,
    suite_ptr: *const u8,
    suite_len: usize,
    domain_ptr: *const u8,
    domain_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    sig_out: *mut u8,
    sig_cap: usize,
) -> i32 {
    let seed = std::slice::from_raw_parts(seed_ptr, seed_len);
    let suite_text =
        String::from_utf8_lossy(std::slice::from_raw_parts(suite_ptr, suite_len)).into_owned();
    let domain_bytes = std::slice::from_raw_parts(domain_ptr, domain_len);
    let payload = std::slice::from_raw_parts(payload_ptr, payload_len);
    let suite = match suite_text.as_str() {
        "ed25519" => Suite::Ed25519,
        "ecdsa-p256" => Suite::EcdsaP256,
        _ => return -2,
    };
    let key = match KeyPair::seeded(suite, seed) {
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
    if signature.len() > sig_cap {
        return -5;
    }
    std::ptr::copy_nonoverlapping(signature.as_ptr(), sig_out, signature.len());
    signature.len() as i32
}

/// Canonicalize a verification route (SI-11): the steps ride as JSON
/// (the s13 crate's serde form), `{canonical_hex, digest_hex}` return
/// through the note buffer.
///
/// # Safety
/// `ptr` names `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_s13_route_canonical(steps_ptr: *const u8, steps_len: usize) -> i32 {
    use unidpp_s13::route::{RouteStep, VerificationRoute};
    let text =
        String::from_utf8_lossy(std::slice::from_raw_parts(steps_ptr, steps_len)).into_owned();
    let outcome = (|| -> Result<serde_json::Value, String> {
        let steps: Vec<RouteStep> =
            serde_json::from_str(&text).map_err(|e| format!("the steps do not parse: {e}"))?;
        let mut route = VerificationRoute::new();
        route.steps = steps;
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        Ok(serde_json::json!({
            "canonical_hex": hex(&route.canonical_bytes()),
            "digest_hex": hex(&route.digest()),
        }))
    })();
    match outcome {
        Ok(value) => canonical_note(value),
        Err(message) => parse_error("route refused", message),
    }
}

/// Canonicalize a coverage report (XB-8): the report rides as JSON,
/// `{canonical_hex, digest_hex}` return through the note buffer.
///
/// # Safety
/// `ptr` names `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_s13_coverage_canonical(
    report_ptr: *const u8,
    report_len: usize,
) -> i32 {
    use unidpp_s13::coverage::CoverageReport;
    let text =
        String::from_utf8_lossy(std::slice::from_raw_parts(report_ptr, report_len)).into_owned();
    let outcome = (|| -> Result<serde_json::Value, String> {
        let report: CoverageReport =
            serde_json::from_str(&text).map_err(|e| format!("the report does not parse: {e}"))?;
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        Ok(serde_json::json!({
            "canonical_hex": hex(&report.canonical_bytes()),
            "digest_hex": hex(&report.digest()),
        }))
    })();
    match outcome {
        Ok(value) => canonical_note(value),
        Err(message) => parse_error("coverage refused", message),
    }
}

/// The composition law (SI-10): the layer vector rides as JSON, the
/// effective level, the bottleneck layer and the policy binding come
/// back through the note buffer.
///
/// # Safety
/// `ptr` names `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn unidpp_s13_compose(
    vector_ptr: *const u8,
    vector_len: usize,
    policy_cap: u64,
) -> i32 {
    use unidpp_s13::route::{compose, LayerVector};
    let text =
        String::from_utf8_lossy(std::slice::from_raw_parts(vector_ptr, vector_len)).into_owned();
    let outcome = (|| -> Result<serde_json::Value, String> {
        if policy_cap > 255 {
            return Err("the policy cap exceeds the harmonization scale".to_string());
        }
        let vector: LayerVector =
            serde_json::from_str(&text).map_err(|e| format!("the vector does not parse: {e}"))?;
        serde_json::to_value(compose(&vector, policy_cap as u8)).map_err(|e| e.to_string())
    })();
    match outcome {
        Ok(value) => canonical_note(value),
        Err(message) => parse_error("compose refused", message),
    }
}
