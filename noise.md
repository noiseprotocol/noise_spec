
Noise
======

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-07-26
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key
agreement.  Noise can describe protocols that consist of a single message as
well as interactive protocols.

Noise messages are described in a language that specifies the exchange of DH
public keys and DH calculations.  The resulting patterns can be instantiated
into concrete protocols based on ciphersuites that fill in the crypto details.


2. Overview
============

2.1. Messages, protocols, and sessions
---------------------------------------

The main concepts in Noise are **messages**, **protocols**, and **sessions**: 

**Messages** are exchanged between parties.  Each message will contain
zero or more public keys followed by an optional payload.  Either the public
keys or payload may be encrypted.

A **protocol** consists of some sequence of messages between a pair of
parties.

Each party will have a **session** which contains the state used to
process messages.

2.2. Descriptors and patterns
------------------------------

A **descriptor** specifies the contents of a message.

A **pattern** specifies the sequence of descriptors that comprise a protocol.

A simple pattern might describe a single **box** message that encrypts one
plaintext from Alice to Bob.  A more complex pattern might describe an
interactive **handshake** whereby Alice and Bob mutually authenticate and
arrive at a shared session key with forward secrecy.

Descriptors and patterns are abstract descriptions of messages and protocols.
They need to be instantiated with a ciphersuite to give concrete messages and
protocols.

Some example Noise patterns are defined in Section 7.

2.3. Sessions and kernels
--------------------------

To simplify the descriptions and improve modularity, a Noise session is
considered to contain a **kernel** object.  The kernel handles all symmetric-key
cryptography.

The kernel can ingest public data as well as secret data, and updates its
internal state based on this data.  The kernel can encrypt and decrypt chunks of
data based on its internal state.

2.4. Key agreement
-------------------

Noise can implement protocols where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that are created and
destroyed during the protocol.

In addition to containing a kernel object, a Noise session can contain two DH
key pairs for its static and ephemeral key pairs, and two DH public keys for the
remote party.

The parties may have prior knowledge of each other's public keys, before
executing a Noise protocol.  This is represented by "pre-messages" that both
parties use to initialize their session state.

2.6. Ciphersuites
------------------

A **ciphersuite** instantiates the symmetric crypto functions needed by the
kernel, as well as the DH functions used for key agreement.

2.7. Conventions
-----------------

Noise comes with some conventions for handling protocol versions and type
fields, length fields, and padding fields.  These aren't a mandatory part of
Noise, but adoption is encouraged, to lead to greater interoperation between
implementations.

3. Ciphersuite functions
=========================

Noise depends on the following constants and functions, which are supplied by a
**ciphersuite**:

 * **`klen`**: A constant specifying the length in bytes of symmetric keys used
 for encryption and decryption.  These same keys are used to accumulate the
 results of DH operations, so `klen` must be >= 32 to provide collision
 resistance.

 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

 * **`ENCRYPT(k, n, authtext, plaintext)` / `DECRYPT(k, n, authtext,
 ciphertext)`**: Encrypts or decrypts data using the cipher key `k` of `klen`
 bytes, and an 8 byte nonce `n` which must be unique for the key `k`.
 Encryption or decryption must be done with an authenticated encryption mode
 with the additional authenticated data `authtext`.  This must be a
 deterministic function (i.e.  it shall not add a random IV; this ensures the
 `GETKEY` function is deterministic).

 * **`GETKEY(k, n)`**:  Calls the `ENCRYPT()` function with cipher key `k` and
 nonce `n` to encrypt a block of `klen` zero bytes.  Returns the first `klen`
 bytes from the encrypted output.  This function is provided separately because
 it can usually be implemented more efficiently than by calling `ENCRYPT` (e.g.
 by skipping the MAC calculation).

 * **`KDF(kdf_key, input)`**: Takes a `kdf_key` equal in length to `k` and some
 input data and returns a new value for the cipher key `k`.  The `kdf_key` will
 be a random secret key and the KDF should implement a "PRF" based on the
 `kdf_key`.  The KDF should also be a collision-resistant hash function given a
 known `kdf_key`.  `HMAC-SHA2-256` is an example KDF.

4.  Kernel state and methods
=============================

A kernel object contains the following state variables:

 * **`k`**: A symmetric key for the cipher algorithm specified in the
 ciphersuite.  This value also mixes together the results of all DH operations.

 * **`n`**: A 64-bit unsigned integer nonce.

 * **`aad`**: A buffer for "additional authenticated data".

A kernel responds to the following methods:

 * **`Initialize(k)`**:  Sets `k` and `n` to all zeros.  Sets `aad` to empty.

 * **`Auth(data)`**:  Appends the length of `data` in bytes to
 `aad` as a little-endian `uint16`.  Then appends `data` to `aad`.

 * **`SetKey(key)`**:  Sets `k` to `key`.

 * **`SetNonce(nonce)`**:  Sets `n` to `nonce`.

 * **`StepKey()`**:  Sets `k` to `GETKEY(k, n)`.  Sets `n` to zero.

 * **`MixKey(data)`**:  Sets `k` to `KDF(GETKEY(k, n), data)`.  Sets `n` to zero.

 * **`EncryptOrAuth(plaintext)`**:  If `k` is all zeros, calls `Auth(plaintext)`
 and returns.  Otherwise calls `ENCRYPT(k, n, aad, plaintext)` to get a
 ciphertext; then increments `n`, sets `aad` to empty, and returns the
 ciphertext.

 * **`DecryptOrAuth(ciphertext)`**:  If `k` is all zeros, calls
 `Auth(ciphertext)` and returns.  Otherwise calls `DECRYPT(k, n, aad,
 ciphertext)` to get a plaintext.  Then increments `n`, sets `aad` to empty, and
 returns the plaintext.

5.  Session state and methods
==============================

Sessions contain a kernel object, plus the following state variables:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

A session responds to the following methods for initialization:

 * **`Initialize()`**:  Calls `Initialize()` on the kernel.  Sets all other
 variables to empty. 
 
 * **`SetStaticKeyPair(keypair)`**:  Sets `s` to `keypair`.

 * **`Auth(data)`**: Calls `Auth(data)` on the kernel.  Can be used to add
 additional context that will be authenticated by the first messages.

 * **`SetKey(key)`**: Calls `SetKey(key)` on the kernel.  Can be used when the
 parties have a pre-shared symmetric key.

A session responds to the following methods for writing and reading messages:

 * **`WriteStatic(buffer)`**:  Writes `EncryptOrAuth(s)` to `buffer`.  

 * **`ReadStatic(buffer)`**:  Reads the correct-size value from `buffer`
 corresponding to the remote party's `EncryptOrAuth(s)` call, calls
 `DecryptOrAuth()` on the result, and sets `rs` to the result.

 * **`WriteEphemeral(buffer)`**:  Sets `e` to `GENERATEKEY()`.  Appends the
 public key from `e` to `buffer`.  Calls `Auth()` on the public key from
 `e`.

 * **`ReadEphemeral(buffer)`**:  Reads `re` from `buffer`.  Calls
 `Auth()` on `re`.

 * **`WritePayload(buffer, payload)`**:  Writes `EncryptOrAuth(payload)` into
 `buffer`.

 * **`ReadPayload(buffer)`**: Reads all remaining data in buffer, calls
 `DecryptOrAuth()` on the data, and returns the result.

 * **`DiffieHellmanSS()`**: Calls `MixKey(DH(s, rs))` on the kernel.

 * **`DiffieHellmanSE()`**: Calls `MixKey(DH(s, re))` on the kernel.

 * **`DiffieHellmanES()`**: Calls `MixKey(DH(e, rs))` on the kernel.

 * **`DiffieHellmanEE()`**: Calls `MixKey(DS(e, re))` on the kernel.

A session provides the following methods for low-level control of encryption:

 * **`SetNonce(nonce)`**: Calls `SetNonce(nonce)` on the kernel.  Can be used
 for protocols where messages might be lost or re-ordered, so nonces have to be
 explicitly transmitted.  Users of this function must take extreme care never to
 reuse a nonce.

 * **`StepKey()`**: Calls `StepKey()` on the kernel.  Can be used to replace the
 existing key `k` for forward secrecy.

 * **`MixKey(data)`**: Calls `MixKey(data)` on the kernel.  Can be used for rare
 cases where a large random nonce or other value needs to be mixed with the key.

6. Descriptors
===============

A descriptor is a comma-separated list containing some of the following tokens.
The tokens describe the sequential actions taken by the writer or reader of a
message.

 * **`s`**: Calls the session's `WriteStatic()` or `ReadStatic()` method. 

 * **`e`**: Calls the session's `WriteEphemeral()` or `ReadEphemeral()` method.

 * **`dhss, dhee, dhse, dhes`**: Calls the appropriate `DiffieHellman__()`
 method on the session.   Note that for the writer, `dhse` corresponds to
 `DiffieHellmanSE()`, but for the reader it corresponds to `DiffieHellmanES()`,
 and vice versa.

7. Message processing
======================

8. Protocol processing
=======================

9. Patterns
============

The following patterns represent the mainstream use of Noise, and can be used
to construct a wide range of protocols.  Of course, other patterns can be
defined in other documents.

Each pattern is given a name, and then described via a sequence of
descriptors.  Descriptors with right-pointing arrows are for messages created
and sent by the protocol initiator; with left-pointing arrows are for messages
sent by the responder.

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These messages aren't sent as part of the protocol proper, but are only used for
their side-effect of initializing `aad`.


9.1. Box patterns
------------------

The following "Box" patterns represent one-shot messages from a sender to a
recipient.  Box naming:

     N  = no static key for sender
     K  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    BoxN:
      <- s
      ------
      -> e, dhes

    BoxK:
      <- s
      -> s
      ------
      -> e, dhes, dhss

    BoxX:
      <- s
      ------
      -> e, dhes, s, dhss

9.2. Handshake patterns
------------------------

The following "Handshake" patterns represent handshakes where the initiator and
responder exchange messages.

    Handshake naming:

     N_ = no static key for initiator
     K_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder
     I_ = static key for inititiator immediately transmitted to responder
 
     _N = no static key for responder
     _K = static key for responder known to initiator
     _E = static key plus a semi-ephemeral key for responder known to initiator
     _X = static key for responder transmitted to initiator


    HandshakeNN:
      -> e
      <- e, dhee

    HandshakeNK:
      <- s
      ------
      -> e, dhes 
      <- e, dhee

    HandshakeNE:
      <- s, e
      ------
      -> e, dhee, dhes 
      <- e, dhee

    HandshakeNX:
      -> e
      <- e, dhee, s, dhse


    HandshakeKN:
      -> s
      ------
      -> e
      <- e, dhee, dhes
    
    HandshakeKK:
      <- s
      -> s
      ------
      -> e, dhes, dhss
      <- e, dhee, dhes

    HandshakeKE:
      <- s, e
      -> s
      ------
      -> e, dhee, dhes, dhse
      <- e, dhee, dhes

    HandshakeKX:
      -> s
      ------
      -> e
      <- e, dhee, dhes, s, dhse


    HandshakeXN:
      -> e
      <- e, dhee
      -> s, dhse

    HandshakeXK:
      <- s
      ------
      -> e, dhes
      <- e, dhee
      -> s, dhse 

    HandshakeXE:
      <- s, e
      ------
      -> e, dhee, dhes
      <- e, dhee
      -> s, dhse 

    HandshakeXX:
      -> e
      <- e, dhee, s, dhse
      -> s, dhse


    HandshakeIN:
      -> e, s
      <- e, dhee, dhes
    
    HandshakeIK:
      <- s
      ------
      -> e, dhes, s, dhss
      <- e, dhee, dhes
    
    HandshakeIE:
      <- s, e
      ------
      -> e, dhee, dhes, s, dhse
      <- e, dhee, dhes
    
    HandshakeIX:
      -> e, s
      <- e, dhee, dhes, s, dhse


10. Ciphersuites
================

10.1. Noise255 and Noise448
---------------------------

These are the default and recommended ciphersuites.

 * **`klen`** = 32

 * **`DH(privkey, pubkey)`:** Curve25519 (Noise255) or Goldilocks (Noise448).
 
 * **`ENCRYPT(k, n, authtext, plainttext)` / `DECRYPT(k, n, authtext,
 ciphertext)`:** `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is
 formed by encoding 32 bits of zeros followed by little-endian encoding of `n`.
 (Earlier implementations of ChaCha20 used a 64-bit nonce, in which case it's
 compatible to encode `n` directly into the ChaCha20 nonce).

 * **`GETKEY(k, n)`:**  The first 32 bytes output from the ChaCha20 block
   function from RFC 7539 with key `k`, nonce `n` encoded as for `ENCRYPT()`,
   and the block count set to 1.  This is the same as calling `ENCRYPT()` on a
   plaintext consisting of 32 bytes of zeros and taking the first 32 bytes of
   output. 

 * **`KDF(kdf_key, input)`:** `HMAC-SHA2-256(kdf_key, input)`.  
 

10.2. AES256-GCM ciphersuites
-----------------------------

These ciphersuites are named Noise255/AES256-GCM and Noise448/AES256-GCM.  The
`DH()` and `KDF()` functions are the same as above.

 * **`klen`** = 32

 * **`DH(privkey, pubkey)`:** Curve25519 (Noise255) or Goldilocks (Noise448).

 * **`ENCRYPT(k, n, authtext, plainttext)` / `DECRYPT(k, n, authtext,
 ciphertext)`:** AES256-GCM from NIST SP800-38-D.  The 96-bit nonce is formed by
 encoding 32 bits of zeros followed by little-endian encoding of `n`.

The `GetKey()` function is defined by encoding the 96-bit nonce from above into
the first 96 bits of two 16-byte blocks `B1` and `B2`.  The final 4 bytes of
`B1` are set to (0, 0, 0, 2).  The final 4 bytes of `B2` are set to (0, 0, 0,
3).  `B1` and `B2` are both encrypted with AES256 and key `k`, and the resulting
ciphertexts `C1` and `C2` are concatenated into the final 32-byte key.  This is
the same as calling `ENCRYPT()` on a plaintext consisting of 32 bytes of zeros
and taking the first 32 bytes of output.


11. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be catastrophic.  Implementations must carefully follow the rules for incrementing nonces after `ENCRYPT()`, `DECRYPT()`, or `GETKEY()` functions. 

To avoid catastrophic key reuse, every party in a Noise protocol should send a fresh ephemeral public key and perform a DH with it prior to sending any encrypted data.  All patterns in Section 6 adhere to this rule.  

12. Rationale
=============

This section collects various design rationale:

Nonces are 64 bits in length because:

 * Some ciphers (e.g. Salsa20) only have 64 bit nonces
 * 64 bit nonces were used in the initial specification and implementations of ChaCha20, so Noise nonces can be used with these implementations.
 * 64 bits allows the entire nonce to be treated as an integer and incremented 
 * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if random nonces are acceptable.

The default ciphersuites use SHA2-256 because:

 * SHA2 is widely available
 * SHA2-256 requires less state than SHA2-512 and produces a sufficient-sized output (32 bytes)

The cipher key must be at least 256 bits because:

 * The cipher key accumulates the DH output, so collision-resistance is desirable

13. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

14. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Additional feedback on spec and pseudocode came from: Jason Donenfeld, Jonathan
Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


