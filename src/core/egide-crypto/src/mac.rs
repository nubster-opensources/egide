//! Keyed message authentication and canonical field encoding.
//!
//! Provides an injective length-prefixed encoding for ordered byte fields and
//! a keyed HMAC-SHA256 tag over those bytes, with constant-time verification.
//! Used to authenticate mutable storage rows (the secrets version pointer and
//! the transit key policy row) and to build tamper-proof AEAD associated data.
