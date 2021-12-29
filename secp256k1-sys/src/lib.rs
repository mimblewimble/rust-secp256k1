// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
//! # secp256k1-sys FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(fuzzing)]
const THIS_UNUSED_CONSTANT_IS_YOUR_WARNING_THAT_ALL_THE_CRYPTO_IN_THIS_LIB_IS_DISABLED_FOR_FUZZING: usize = 0;

#[macro_use]
mod macros;
pub mod types;

#[cfg(feature = "recovery")]
pub mod recovery;

use core::{hash, slice, ptr};
use types::*;

/// Flag for context to enable no precomputation
pub const SECP256K1_START_NONE: c_uint = 1;
/// Flag for context to enable verification precomputation
pub const SECP256K1_START_VERIFY: c_uint = 1 | (1 << 8);
/// Flag for context to enable signing precomputation
pub const SECP256K1_START_SIGN: c_uint = 1 | (1 << 9);
/// Flag for context to enable commitment precomputation
pub const SECP256K1_START_COMMIT: c_uint = 1 | (1 << 10);
/// Flag for keys to indicate uncompressed serialization format
#[allow(unused_parens)]
pub const SECP256K1_SER_UNCOMPRESSED: c_uint = (1 << 1);
/// Flag for keys to indicate compressed serialization format
pub const SECP256K1_SER_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

/// A nonce generation function. Ordinary users of the library
/// never need to see this type; only if you need to control
/// nonce generation do you need to use it. I have deliberately
/// made this hard to do: you have to write your own wrapper
/// around the FFI functions to use it. And it's an unsafe type.
/// Nonces are generated deterministically by RFC6979 by
/// default; there should be no need to ever change this.
pub type NonceFn = Option<unsafe extern "C" fn(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
    attempt: c_uint,
) -> c_int>;

/// Hash function to use to post-process an ECDH point to get
/// a shared secret.
pub type EcdhHashFn = Option<unsafe extern "C" fn(
    output: *mut c_uchar,
    x: *const c_uchar,
    y: *const c_uchar,
    data: *mut c_void,
) -> c_int>;

///  Same as secp256k1_nonce function with the exception of accepting an
///  additional pubkey argument and not requiring an attempt argument. The pubkey
///  argument can protect signature schemes with key-prefixed challenge hash
///  inputs against reusing the nonce when signing with the wrong precomputed
///  pubkey.
pub type SchnorrNonceFn = Option<unsafe extern "C" fn(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    xonly_pk32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
) -> c_int>;

/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
#[derive(Clone, Debug)]
#[repr(C)] pub struct Context(c_int);

/// Secp256k1 aggsig context. As above, needs to be destroyed with
/// `secp256k1_aggsig_context_destroy`
#[derive(Clone, Debug)]
#[repr(C)] pub struct AggSigContext(c_int);

/// Secp256k1 scratch space
#[derive(Clone, Debug)]
#[repr(C)] pub struct ScratchSpace(c_int);

/// Secp256k1 bulletproof generators
#[derive(Clone, Debug)]
#[repr(C)] pub struct BulletproofGenerators(c_int);

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    /// Creates an "uninitialized" FFI public key which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new public key usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        PublicKey(data)
    }

    /// Returns the underlying FFI opaque representation of the public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

impl hash::Hash for PublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
pub struct Signature([c_uchar; 64]);
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

impl Signature {
    /// Creates an "uninitialized" FFI signature which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new signature usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        Signature(data)
    }

    /// Returns the underlying FFI opaque representation of the signature
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

/// Library-internal representation of a Secp256k1 aggsig partial signature
#[repr(C)]
pub struct AggSigPartialSignature([c_uchar; 32]);
impl_array_newtype!(AggSigPartialSignature, c_uchar, 32);
impl_raw_debug!(AggSigPartialSignature);

impl AggSigPartialSignature {
    /// Creates an "uninitialized" FFI x-only aggsig partial signature which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 32])
    }
    /// Create a new aggsig partial signature usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 32]) -> Self {
        AggSigPartialSignature(data)
    }
}

#[repr(C)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

impl XOnlyPublicKey {
    /// Creates an "uninitialized" FFI x-only public key which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new x-only public key usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        XOnlyPublicKey(data)
    }

    /// Returns the underlying FFI opaque representation of the x-only public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

impl hash::Hash for XOnlyPublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

#[repr(C)]
pub struct KeyPair([c_uchar; 96]);
impl_array_newtype!(KeyPair, c_uchar, 96);
impl_raw_debug!(KeyPair);

impl KeyPair {
    /// Creates an "uninitialized" FFI keypair which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 96])
    }

    /// Create a new keypair usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 96]) -> Self {
        KeyPair(data)
    }

    /// Returns the underlying FFI opaque representation of the x-only public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 96] {
        self.0
    }
}

impl hash::Hash for KeyPair {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

extern "C" {
    pub static secp256k1_nonce_function_rfc6979: NonceFn;

    pub static secp256k1_nonce_function_default: NonceFn;

    pub static secp256k1_nonce_function_bip340: SchnorrNonceFn;

    pub static secp256k1_context_no_precomp: *const Context;

    // Contexts
    pub fn secp256k1_context_preallocated_size(flags: c_uint) -> size_t;

    pub fn secp256k1_context_preallocated_create(prealloc: *mut c_void, flags: c_uint) -> *mut Context;

    pub fn secp256k1_context_preallocated_destroy(cx: *mut Context);

    pub fn secp256k1_context_preallocated_clone_size(cx: *const Context) -> size_t;

    pub fn secp256k1_context_preallocated_clone(cx: *const Context, prealloc: *mut c_void) -> *mut Context;

    pub fn secp256k1_context_randomize(cx: *mut Context,
                                       seed32: *const c_uchar)
                                       -> c_int;

    // Scratch space
    pub fn secp256k1_scratch_space_create(cx: *mut Context,
                                          max_size: size_t)
                                          -> *mut ScratchSpace;

    pub fn secp256k1_scratch_space_destroy(sp: *mut ScratchSpace);

    // Pubkeys
    pub fn secp256k1_ec_pubkey_parse(cx: *const Context, pk: *mut PublicKey,
                                     input: *const c_uchar, in_len: size_t)
                                     -> c_int;

    pub fn secp256k1_ec_pubkey_serialize(cx: *const Context, output: *mut c_uchar,
                                         out_len: *mut size_t, pk: *const PublicKey,
                                         compressed: c_uint)
                                         -> c_int;

    // Signatures
    pub fn secp256k1_ecdsa_signature_parse_der(cx: *const Context, sig: *mut Signature,
                                               input: *const c_uchar, in_len: size_t)
                                               -> c_int;

    pub fn secp256k1_ecdsa_signature_parse_compact(cx: *const Context, sig: *mut Signature,
                                                   input64: *const c_uchar)
                                                   -> c_int;

    pub fn ecdsa_signature_parse_der_lax(cx: *const Context, sig: *mut Signature,
                                         input: *const c_uchar, in_len: size_t)
                                         -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_der(cx: *const Context, output: *mut c_uchar,
                                                   out_len: *mut size_t, sig: *const Signature)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_compact(cx: *const Context, output64: *mut c_uchar,
                                                       sig: *const Signature)
                                                       -> c_int;

    pub fn secp256k1_ecdsa_signature_normalize(cx: *const Context, out_sig: *mut Signature,
                                               in_sig: *const Signature)
                                               -> c_int;

    pub fn secp256k1_ec_seckey_verify(cx: *const Context,
                                      sk: *const c_uchar) -> c_int;

    pub fn secp256k1_ec_privkey_negate(cx: *const Context,
                                       sk: *mut c_uchar) -> c_int;

    pub fn secp256k1_ec_privkey_tweak_add(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_privkey_tweak_mul(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    // EC
    pub fn secp256k1_ec_pubkey_create(cx: *const Context, pk: *mut PublicKey,
                                      sk: *const c_uchar) -> c_int;


    pub fn secp256k1_ec_pubkey_negate(cx: *const Context,
                                      pk: *mut PublicKey) -> c_int;


    pub fn secp256k1_ec_pubkey_tweak_add(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_mul(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_pubkey_combine(cx: *const Context,
                                       out: *mut PublicKey,
                                       ins: *const *const PublicKey,
                                       n: c_int)
                                       -> c_int;

    pub fn secp256k1_ecdh(cx: *const Context,
                          output: *mut c_uchar,
                          pubkey: *const PublicKey,
                          seckey: *const c_uchar)
                          -> c_int;
}

#[cfg(not(fuzzing))]
extern "C" {
    // ECDSA
    pub fn secp256k1_ecdsa_verify(cx: *const Context,
                                  sig: *const Signature,
                                  msg32: *const c_uchar,
                                  pk: *const PublicKey)
                                  -> c_int;

    pub fn secp256k1_ecdsa_sign(cx: *const Context,
                                sig: *mut Signature,
                                msg32: *const c_uchar,
                                sk: *const c_uchar,
                                noncefn: NonceFn,
                                noncedata: *const c_void)
                                -> c_int;

    // Schnorr Signatures
    pub fn secp256k1_schnorrsig_sign(
        cx: *const Context,
        sig: *mut c_uchar,
        msg32: *const c_uchar,
        keypair: *const KeyPair,
        noncefp: SchnorrNonceFn,
        noncedata: *const c_void
    ) -> c_int;

    pub fn secp256k1_schnorrsig_verify(
        cx: *const Context,
        sig64: *const c_uchar,
        msg32: *const c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int;

    // AGGSIG (Schnorr) Multisig
    pub fn secp256k1_aggsig_context_create(cx: *const Context,
                                           pks: *const PublicKey,
                                           n_pks: size_t,
                                           seed32: *const c_uchar)
                                           -> *mut AggSigContext;

    pub fn secp256k1_aggsig_context_destroy(aggctx: *mut AggSigContext);

    pub fn secp256k1_aggsig_generate_nonce(cx: *const Context,
                                           aggctx: *mut AggSigContext,
                                           index: size_t)
                                           -> c_int;

    pub fn secp256k1_aggsig_partial_sign(cx: *const Context,
                                         aggctx: *mut AggSigContext,
                                         sig: *mut AggSigPartialSignature,
                                         msghash32: *const c_uchar,
                                         seckey32: *const c_uchar,
                                         index: size_t)
                                         -> c_int;

    pub fn secp256k1_aggsig_combine_signatures(cx: *const Context,
                                               aggctx: *mut AggSigContext,
                                               sig64: *mut Signature,
                                               partial: *const AggSigPartialSignature,
                                               index: size_t)
                                               -> c_int;

    pub fn secp256k1_aggsig_build_scratch_and_verify(cx: *const Context,
                                                     sig64: *const Signature,
                                                     msg32: *const c_uchar,
                                                     pks: *const PublicKey,
                                                     n_pubkeys: size_t)
                                                     -> c_int;

    // AGGSIG (single sig or single-signer Schnorr)
    pub fn secp256k1_aggsig_export_secnonce_single(cx: *const Context,
                                                   secnonce32: *mut c_uchar,
                                                   seed32: *const c_uchar)
    -> c_int;

    pub fn secp256k1_aggsig_sign_single(cx: *const Context,
                                        sig: *mut Signature,
                                        msg32: *const c_uchar,
                                        seckey32: *const c_uchar,
                                        secnonce32: *const c_uchar,
                                        extra32: *const c_uchar,
                                        pubnonce_for_e: *const PublicKey,
                                        pubnonce_total: *const PublicKey,
                                        pubkey_for_e: *const PublicKey,
                                        seed32: *const c_uchar)
                                        -> c_int;

    pub fn secp256k1_aggsig_verify_single(cx: *const Context,
                                          sig: *const Signature,
                                          msg32: *const c_uchar,
                                          pubnonce: *const PublicKey,
                                          pk: *const PublicKey,
                                          pk_total: *const PublicKey,
                                          extra_pubkey: *const PublicKey,
                                          is_partial: c_uint)
                                          -> c_int;

    pub fn secp256k1_schnorrsig_verify_batch(cx: *const Context,
                                             scratch: *mut ScratchSpace,
                                             sig: *const *const c_uchar,
                                             msg32: *const *const c_uchar,
                                             pk: *const *const PublicKey,
                                             n_sigs: size_t)
                                             -> c_int;

    pub fn secp256k1_aggsig_add_signatures_single(cx: *const Context,
                                                  ret_sig: *mut Signature,
                                                  sigs: *const *const c_uchar,
                                                  num_sigs: size_t,
                                                  pubnonce_total: *const PublicKey)
                                                  -> c_int;

    // Parse a 33-byte commitment into 64 byte internal commitment object
    pub fn secp256k1_pedersen_commitment_parse(cx: *const Context,
                                               commit: *mut c_uchar,
                                               input: *const c_uchar)
                                               -> c_int;

    // Serialize a 64-byte commit object into a 33 byte serialized byte sequence
    pub fn secp256k1_pedersen_commitment_serialize(cx: *const Context,
                                                   output: *mut c_uchar,
                                                   commit: *const c_uchar)
                                                   -> c_int;


    // Generates a pedersen commitment: *commit = blind * G + value * G2.
    // The commitment is 33 bytes, the blinding factor is 32 bytes.
    pub fn secp256k1_pedersen_commit(ctx: *const Context,
                                     commit: *mut c_uchar,
                                     blind: *const c_uchar,
                                     value: u64,
                                     value_gen: *const c_uchar,
                                     blind_gen: *const c_uchar)
                                     -> c_int;

    // Generates a pedersen commitment: *commit = blind * G + value * G2.
    // The commitment is 33 bytes, the blinding factor and the value are 32 bytes.
    pub fn secp256k1_pedersen_blind_commit(ctx: *const Context,
                                           commit: *mut c_uchar,
                                           blind: *const c_uchar,
                                           value: *const c_uchar,
                                           value_gen: *const c_uchar,
                                           blind_gen: *const c_uchar)
                                           -> c_int;

    // Get the public key of a pedersen commitment
    pub fn secp256k1_pedersen_commitment_to_pubkey(cx: *const Context,
                                                   pk: *mut PublicKey,
                                                   commit: *const c_uchar)
                                                   -> c_int;

    // Get a pedersen commitment from a pubkey
    pub fn secp256k1_pubkey_to_pedersen_commitment(cx: *const Context,
                                                   commit: *mut c_uchar,
                                                   pk: *const PublicKey)
                                                   -> c_int;

    // Takes a list of n pointers to 32 byte blinding values, the first negs
    // of which are treated with positive sign and the rest negative, then
    // calculates an additional blinding value that adds to zero.
    pub fn secp256k1_pedersen_blind_sum(ctx: *const Context,
                                        blind_out: *const c_uchar,
                                        blinds: *const *const c_uchar,
                                        n: size_t,
                                        npositive: size_t)
                                        -> c_int;

    // Takes two list of 64-byte commitments and sums the first set, subtracts
    // the second and returns the resulting commitment.
    pub fn secp256k1_pedersen_commit_sum(ctx: *const Context,
                                         commit_out: *const c_uchar,
                                         commits: *const *const c_uchar,
                                         pcnt: size_t,
                                         ncommits: *const *const c_uchar,
                                         ncnt: size_t)
                                         -> c_int;

    // Calculate blinding factor for switch commitment x + H(xG+vH | xJ)
    pub fn secp256k1_blind_switch(ctx: *const Context,
                                  blind_switch: *mut c_uchar,
                                  blind: *const c_uchar,
                                  value: u64,
                                  value_gen: *const c_uchar,
                                  blind_gen: *const c_uchar,
                                  switch_pubkey: *const c_uchar)
                                  -> c_int;

    // Takes two list of 64-byte commitments and sums the first set and
    // subtracts the second and verifies that they sum to 0.
    pub fn secp256k1_pedersen_verify_tally(ctx: *const Context,
                                           commits: *const *const c_uchar,
                                           pcnt: size_t,
                                           ncommits: *const *const c_uchar,
                                           ncnt: size_t)
                                           -> c_int;

    pub fn secp256k1_rangeproof_info(ctx: *const Context,
                                     exp: *mut c_int,
                                     mantissa: *mut c_int,
                                     min_value: *mut u64,
                                     max_value: *mut u64,
                                     proof: *const c_uchar,
                                     plen: size_t)
                                     -> c_int;

    pub fn secp256k1_rangeproof_rewind(ctx: *const Context,
                                       blind_out: *mut c_uchar,
                                       value_out: *mut u64,
                                       message_out: *mut c_uchar,
                                       outlen: *mut size_t,
                                       nonce: *const c_uchar,
                                       min_value: *mut u64,
                                       max_value: *mut u64,
                                       commit: *const c_uchar,
                                       proof: *const c_uchar,
                                       plen: size_t,
                                       extra_commit: *const c_uchar,
                                       extra_commit_len: size_t,
                                       gen: *const c_uchar)
                                       -> c_int;

    pub fn secp256k1_rangeproof_verify(ctx: *const Context,
                                       min_value: &mut u64,
                                       max_value: &mut u64,
                                       commit: *const c_uchar,
                                       proof: *const c_uchar,
                                       plen: size_t,
                                       extra_commit: *const c_uchar,
                                       extra_commit_len: size_t,
                                       gen: *const c_uchar)
                                       -> c_int;

    pub fn secp256k1_rangeproof_sign(ctx: *const Context,
                                     proof: *mut c_uchar,
                                     plen: *mut size_t,
                                     min_value: u64,
                                     commit: *const c_uchar,
                                     blind: *const c_uchar,
                                     nonce: *const c_uchar,
                                     exp: c_int,
                                     min_bits: c_int,
                                     value: u64,
                                     message: *const c_uchar,
                                     msg_len: size_t,
                                     extra_commit: *const c_uchar,
                                     extra_commit_len: size_t,
                                     gen: *const c_uchar)
                                     -> c_int;

    pub fn secp256k1_bulletproof_generators_create(ctx: *const Context,
                                                   blinding_gen: *const c_uchar,
                                                   n: size_t)
                                                   -> *mut BulletproofGenerators;

    pub fn secp256k1_bulletproof_generators_destroy(ctx: *const Context,
                                                    gen: *mut BulletproofGenerators);

    pub fn secp256k1_bulletproof_rangeproof_prove(ctx: *const Context,
                                                  scratch: *mut ScratchSpace,
                                                  gens: *const BulletproofGenerators,
                                                  proof: *mut c_uchar,
                                                  plen: *mut size_t,
                                                  tau_x: *mut c_uchar,
                                                  t_one: *mut PublicKey,
                                                  t_two: *mut PublicKey,
                                                  value: *const u64,
                                                  min_value: *const u64,
                                                  blind: *const *const c_uchar,
                                                  commits: *const *const c_uchar,
                                                  n_commits: size_t,
                                                  value_gen: *const c_uchar,
                                                  nbits: size_t,
                                                  nonce: *const c_uchar,
                                                  private_nonce: *const c_uchar,
                                                  extra_commit: *const c_uchar,
                                                  extra_commit_len: size_t,
                                                  message: *const c_uchar)
                                                  -> c_int;

    pub fn secp256k1_bulletproof_rangeproof_verify(ctx: *const Context,
                                                   scratch: *mut ScratchSpace,
                                                   gens: *const BulletproofGenerators,
                                                   proof: *const c_uchar,
                                                   plen: size_t,
                                                   min_value: *const u64,
                                                   commit: *const c_uchar,
                                                   n_commits: size_t,
                                                   nbits: size_t,
                                                   value_gen: *const c_uchar,
                                                   extra_commit: *const c_uchar,
                                                   extra_commit_len: size_t)
                                                   -> c_int;

    pub fn secp256k1_bulletproof_rangeproof_verify_multi(ctx: *const Context,
                                                         scratch: *mut ScratchSpace,
                                                         gens: *const BulletproofGenerators,
                                                         proofs: *const *const c_uchar,
                                                         n_proofs: size_t,
                                                         plen: size_t,
                                                         min_value: *const *const u64,
                                                         commits: *const *const c_uchar,
                                                         n_commits: size_t,
                                                         nbits: size_t,
                                                         value_gen: *const c_uchar,
                                                         extra_commit: *const *const c_uchar,
                                                         extra_commit_len: *const size_t)
                                                         -> c_int;

    pub fn secp256k1_bulletproof_rangeproof_rewind(ctx: *const Context,
                                                   value: *mut u64,
                                                   blind: *mut c_uchar,
                                                   proof: *const c_uchar,
                                                   plen: size_t,
                                                   min_value: u64,
                                                   commit: *const c_uchar,
                                                   value_gen: *const c_uchar,
                                                   nonce: *const c_uchar,
                                                   extra_commit: *const c_uchar,
                                                   extra_commit_len: size_t,
                                                   message: *mut c_uchar)
                                                   -> c_int;

}


/// A reimplementation of the C function `secp256k1_context_create` in rust.
///
/// This function allocates memory, the pointer should be deallocated using `secp256k1_context_destroy`
/// A failure to do so will result in a memory leak.
///
/// This will create a secp256k1 raw context.
// Returns: a newly created context object.
//  In:      flags: which parts of the context to initialize.
#[no_mangle]
#[cfg(all(feature = "std", not(rust_secp_no_symbol_renaming)))]
pub unsafe extern "C" fn rustsecp256k1_context_create(flags: c_uint) -> *mut Context {
    use core::mem;
    use std::alloc;
    assert!(ALIGN_TO >= mem::align_of::<usize>());
    assert!(ALIGN_TO >= mem::align_of::<&usize>());
    assert!(ALIGN_TO >= mem::size_of::<usize>());

    // We need to allocate `ALIGN_TO` more bytes in order to write the amount of bytes back.
    let bytes = secp256k1_context_preallocated_size(flags) + ALIGN_TO;
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    let ptr = alloc::alloc(layout);
    (ptr as *mut usize).write(bytes);
    // We must offset a whole ALIGN_TO in order to preserve the same alignment
    // this means we "lose" ALIGN_TO-size_of(usize) for padding.
    let ptr = ptr.add(ALIGN_TO) as *mut c_void;
    secp256k1_context_preallocated_create(ptr, flags)
}

#[cfg(all(feature = "std", not(rust_secp_no_symbol_renaming)))]
pub unsafe fn secp256k1_context_create(flags: c_uint) -> *mut Context {
    rustsecp256k1_context_create(flags)
}

/// A reimplementation of the C function `secp256k1_context_destroy` in rust.
///
/// This function destroys and deallcates the context created by `secp256k1_context_create`.
///
/// The pointer shouldn't be used after passing to this function, consider it as passing it to `free()`.
///
#[no_mangle]
#[cfg(all(feature = "std", not(rust_secp_no_symbol_renaming)))]
pub unsafe extern "C" fn rustsecp256k1_context_destroy(ctx: *mut Context) {
    use std::alloc;
    secp256k1_context_preallocated_destroy(ctx);
    let ptr = (ctx as *mut u8).sub(ALIGN_TO);
    let bytes = (ptr as *mut usize).read();
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    alloc::dealloc(ptr, layout);
}

#[cfg(all(feature = "std", not(rust_secp_no_symbol_renaming)))]
pub unsafe fn secp256k1_context_destroy(ctx: *mut Context) {
    rustsecp256k1_context_destroy(ctx)
 }
/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an illegal argument is passed to
/// an API call. It will only trigger for violations that are mentioned
/// explicitly in the header. **This will cause a panic**.
///
/// The philosophy is that these shouldn't be dealt with through a
/// specific return value, as calling code should not have branches to deal with
/// the case that this code itself is broken.
///
/// On the other hand, during debug stage, one would want to be informed about
/// such mistakes, and the default (crashing) may be inadvisable.
/// When this callback is triggered, the API function called is guaranteed not
/// to cause a crash, though its return value and output arguments are
/// undefined.
///
/// See also secp256k1_default_error_callback_fn.
///
#[no_mangle]
#[cfg(not(rust_secp_no_symbol_renaming))]
pub unsafe extern "C" fn rustsecp256k1_default_illegal_callback_fn(message: *const c_char, _data: *mut c_void) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] illegal argument. {}", msg);
}

/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an internal consistency check
/// fails. **This will cause a panic**.
///
/// This can only trigger in case of a hardware failure, miscompilation,
/// memory corruption, serious bug in the library, or other error would can
/// otherwise result in undefined behaviour. It will not trigger due to mere
/// incorrect usage of the API (see secp256k1_default_illegal_callback_fn
/// for that). After this callback returns, anything may happen, including
/// crashing.
///
/// See also secp256k1_default_illegal_callback_fn.
///
#[no_mangle]
#[cfg(not(rust_secp_no_symbol_renaming))]
pub unsafe extern "C" fn rustsecp256k1_default_error_callback_fn(message: *const c_char, _data: *mut c_void) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] internal consistency check failed {}", msg);
}

#[cfg(not(rust_secp_no_symbol_renaming))]
unsafe fn strlen(mut str_ptr: *const c_char) -> usize {
    let mut ctr = 0;
    while *str_ptr != '\0' as c_char {
        ctr += 1;
        str_ptr = str_ptr.offset(1);
    }
    ctr
}


/// A trait for producing pointers that will always be valid in C. (assuming NULL pointer is a valid no-op)
/// Rust doesn't promise what pointers does it give to ZST (https://doc.rust-lang.org/nomicon/exotic-sizes.html#zero-sized-types-zsts)
/// In case the type is empty this trait will give a NULL pointer, which should be handled in C.
///
pub trait CPtr {
    type Target;
    fn as_c_ptr(&self) -> *const Self::Target;
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target;
}

impl<T> CPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            ptr::null()
        } else {
            self.as_ptr()
        }
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        if self.is_empty() {
            ptr::null_mut::<Self::Target>()
        } else {
            self.as_mut_ptr()
        }
    }
}

#[cfg(fuzzing)]
mod fuzz_dummy {
    use super::*;

    // ECDSA
    /// Verifies that sig is msg32||pk[..32]
    pub unsafe fn secp256k1_ecdsa_verify(cx: *const Context,
                                         sig: *const Signature,
                                         msg32: *const c_uchar,
                                         pk: *const PublicKey)
                                         -> c_int {
        // Check context is built for verification
        let mut new_pk = (*pk).clone();
        let _ = secp256k1_ec_pubkey_tweak_add(cx, &mut new_pk, msg32);
        // Actually verify
        let sig_sl = slice::from_raw_parts(sig as *const u8, 64);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);
        if &sig_sl[..32] == msg_sl && sig_sl[32..] == (*pk).0[0..32] {
            1
        } else {
            0
        }
    }

    /// Sets sig to msg32||pk[..32]
    pub unsafe fn secp256k1_ecdsa_sign(cx: *const Context,
                                       sig: *mut Signature,
                                       msg32: *const c_uchar,
                                       sk: *const c_uchar,
                                       _noncefn: NonceFn,
                                       _noncedata: *const c_void)
                                       -> c_int {
        // Check context is built for signing (and compute pk)
        let mut new_pk = PublicKey::new();
        if secp256k1_ec_pubkey_create(cx, &mut new_pk, sk) != 1 {
            return 0;
        }
        // Sign
        let sig_sl = slice::from_raw_parts_mut(sig as *mut u8, 64);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);
        sig_sl[..32].copy_from_slice(msg_sl);
        sig_sl[32..].copy_from_slice(&new_pk.0[..32]);
        1
    }
}

#[cfg(fuzzing)]
pub use self::fuzz_dummy::*;

#[cfg(test)]
mod tests {
    #[cfg(not(rust_secp_no_symbol_renaming))]
    #[test]
    fn test_strlen() {
        use std::ffi::CString;
        use super::strlen;

        let orig = "test strlen \t \n";
        let test = CString::new(orig).unwrap();

        assert_eq!(orig.len(), unsafe {strlen(test.as_ptr())});
    }
}

