//! Tiny shared helpers used across modules.

/// Encode bytes as `0x`-prefixed lowercase hex.
pub fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
