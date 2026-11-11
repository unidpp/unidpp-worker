//! A wasm-target shim for `getrandom` 0.2: the binding crate's
//! deterministic paths (seeded keys, ed25519 signing, sha256) never
//! reach the operating system's RNG, so the shim fills zeros. The
//! point of the shim is the ABI: the real crate's js bindings drag
//! wasm-bindgen imports into the module, and the Worker's module must
//! instantiate with no imports at all.

#[derive(Debug, Clone, Copy)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the wasm rng shim")
    }
}

impl std::error::Error for Error {}

/// Fill `dest` with zeros (the shim's stand-in for the OS RNG).
pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    for byte in dest.iter_mut() {
        *byte = 0;
    }
    Ok(())
}

/// The convenience form some callers use.
pub fn fill_bytes(dest: &mut [u8]) {
    let _ = getrandom(dest);
}
