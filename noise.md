
Noise
======

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-08-26
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key
agreement.  Noise can describe protocols that consist of a single message as
well as interactive protocols.

2. Overview
============

2.1. Messages, protocols, and sessions
---------------------------------------

**Messages** are exchanged between parties.  Each message will contain
zero or more public keys followed by an optional payload.  Either the public
keys or payload may be encrypted.

A **protocol** consists of some sequence of messages between a pair of
parties.

Each party will have a **session** which contains the state used to
process messages.

2.2. Descriptors, patterns, and ciphersuites
---------------------------------------------

A **descriptor** specifies the contents of a message.

A **pattern** specifies the sequence of descriptors that comprise a protocol.

A simple pattern might describe a single message that encrypts one
plaintext from Alice to Bob.  A more complex pattern might describe an
interactive protocol where Alice and Bob mutually authenticate and
arrive at a shared session key with forward secrecy.

Descriptors and patterns are abstract descriptions of messages and protocols.
They need to be instantiated with a **ciphersuite** to give concrete messages
and protocols.

2.3. Kernels
-------------

To simplify the descriptions and improve modularity, a session contains a
**kernel**.  The kernel handles all symmetric-key cryptography.

The kernel can mix inputs into its internal state, and can encrypt and decrypt
data based on its internal state.

2.4. Key agreement
-------------------

Noise can implement protocols where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that are created during
the protocol.

The parties may have prior knowledge of each other's public keys, before
executing a Noise protocol.  This is represented by "pre-messages" that both
parties use to initialize their session state.

2.7. Conventions
-----------------

Noise comes with some conventions for handling protocol versions and type
fields, length fields, and padding fields.  These aren't a mandatory part of
Noise, but adoption is encouraged.

3. Ciphersuite functions
=========================

Noise depends on the following constants and functions, which are supplied by a
**ciphersuite**:

 * **`klen`**: A constant specifying the length in bytes of symmetric keys used
 for encryption.  These keys are used to accumulate the results of DH
 operations, so `klen` must be >= 32 to provide collision resistance.  32 is
 recommended.

 * **`hlen`**: A constant specifying the length in bytes of hash outputs.  Must
 be >= 32 bytes to provide collision resistance.  32 is recommended.

 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts data using the cipher key `k` of
 `klen` bytes, and a 64-bit unsigned integer nonce `n` which must be unique for
 the key `k`.  Encryption must be done with an "AEAD" encryption mode with the
 associated data `ad`.  This must be a deterministic function (i.e.  it shall
 not add a random IV; this ensures the `GETKEY()` function is deterministic).

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts data using the cipher key `k`
 of `klen` bytes, a 64-bit unsigned integer nonce `n`, and associated data `ad`.

 * **`GETKEY(k, n)`**:  Calls the `ENCRYPT()` function with cipher key `k` and
 nonce `n` to encrypt a block of `klen` zero bytes.  Returns the first `klen`
 bytes from the encrypted output.  This function can usually be implemented more
 efficiently than by calling `ENCRYPT` (e.g.  by skipping the MAC calculation).

 * **`KDF(kdf_key, input)`**: Takes a `kdf_key` of `klen` bytes and some
 input data and returns a new value for the cipher key `k`.  The `kdf_key` will
 be a random secret key and the KDF should implement a "PRF" based on the
 `kdf_key`.  The KDF should also be a collision-resistant hash function given a
 known `kdf_key`.  `HMAC-SHA2-256` is an example KDF.

 * **`HASH(data)`**: Hashes some input data and returns a collision-resistant
 hash output of `hlen` bytes. SHA2-256 is an example hash function.

4.  Kernel state and methods
=============================

A kernel object contains the following state variables:

 * **`k`**: A symmetric key of `klen` bytes for the cipher algorithm specified
 in the ciphersuite.  This value mixes together the results of all DH
 operations, and is used for encryption.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with with `k`
 for encryption.

 * **`h`**: Either empty or `hlen` bytes containtaining a hash output.  This
 value mixes together relevant handshake data, and is then authenticated by
 encryption.
 
A kernel responds to the following methods:

 * **`InitializeKernel()`**:  Sets `k` to all zero bytes, `n` to zero, and `h`
 to empty.

 * **`SetNonce(nonce)`**:  Sets `n` to `nonce`.

 * **`StepKey()`**:  Sets `k` to `GETKEY(k, n)`.  Sets `n` to zero.

 * **`MixKey(data)`**:  Sets `k` to `KDF(GETKEY(k, n), data)`.  Sets `n` to zero.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  In other words,
 replaces `h` by the hash of `h` with with `data` appended.

 * **`ClearHash(data)`**: Sets `h` to empty.

 * **`Split()`**:  Creates a new child kernel, with `n` set to 0 and `h` copied
 from this kernel.  Sets the child's `k` to the output of `GETKEY(k, n)`, and
 increments `n`.  Then sets its own `k` to the output of `GETKEY(k, n)` and sets
 `n` to zero.  Then returns the child.

 * **`Encrypt(plaintext)`**:  If `k` is all zeros this returns the plaintext
 without encrypting.  Otherwise calls `ENCRYPT(k, n, h, plaintext)` to get a
 ciphertext, then increments `n` and returns the ciphertext.

 * **`Decrypt(ciphertext)`**:  If `k` is all zeros this returns the ciphertext
 without decrypting.  Otherwise calls `DECRYPT(k, n, h, ciphertext)` to get a
 plaintext, then increments `n` and returns the plaintext.

5.  Session state and methods
==============================

Sessions contain a kernel object, plus the following state variables:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

A session responds to all of the kernel methods by forwarding them to the
kernel.  In addition, a session responds to the following methods for
initialization:

 * **`InitializeSession()`**:  Calls `InitializeKernel()`.  Sets all other
 variables to empty. 
 
 * **`SetStaticKeyPair(keypair)`**:  Sets `s` to `keypair`.

A session responds to the following methods for writing and reading messages:

 * **`WriteStatic(buffer)`**:  Writes `Encrypt(s)` to `buffer` and calls
 `MixHash(s)`.  

 * **`ReadStatic(buffer)`**:  Reads the correct amount of data from `buffer`
 corresponding to the remote party's `Encrypt(s)` call.  Then calls `Decrypt()`
 on the read data and stores the result in `rs`.  Calls `MixHash(rs)`.

 * **`WriteEphemeral(buffer)`**:  Sets `e` to `GENERATE_KEYPAIR()`.  Appends the
 public key from `e` to `buffer`.

 * **`ReadEphemeral(buffer)`**:  Reads `re` from `buffer`.

 * **`WritePayload(buffer, payload)`**:  Writes `Encrypt(payload)` into
 `buffer`.

 * **`ReadPayload(buffer)`**: Reads all remaining data in buffer, calls
 `Decrypt()` on the data to get the payload.

 * **`DiffieHellmanSS()`**: Calls `MixKey(DH(s, rs))` on the kernel.

 * **`DiffieHellmanSE()`**: Calls `MixKey(DH(s, re))` on the kernel.

 * **`DiffieHellmanES()`**: Calls `MixKey(DH(e, rs))` on the kernel.

 * **`DiffieHellmanEE()`**: Calls `MixKey(DS(e, re))` on the kernel.

6. Descriptors and patterns
============================

A descriptor is a comma-separated list containing some of the following tokens.
The tokens describe the sequential actions taken by the writer or reader of a
message.

 * **`s`**: Calls the session's `WriteStatic()` or `ReadStatic()` method. 

 * **`e`**: Calls the session's `WriteEphemeral()` or `ReadEphemeral()` method.

 * **`dhss, dhee, dhse, dhes`**: Given `dhXY` calls `DiffieHellmanXY()` for the
 writer and `DiffieHellmanYX()` for the reader.

A pattern is a sequence of descriptors. Descriptors with right-pointing arrows
are for messages created and sent by the protocol initiator; with left-pointing
arrows are for messages sent by the responder.  The following pattern describes
an unauthenticated DH handshake:

      -> e
      <- e, dhee

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These messages aren't sent as part of the protocol proper, but are only used for
their side-effect of calling `MixHash()`.  

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral:

      <- s
      ------
      -> e, dhes 
      <- e, dhee

7. Message processing 
======================

Writing a message requires:

 * A session
 
 * A buffer to write the message into

 * A descriptor 

 * Payload data (may be zero bytes).

First the descriptor is processed sequentially.  Then `WritePayload(buffer,
payload)` is called on the session.

To read the message the descriptor is processed sequentially.  Then
`ReadPayload(buffer)` is called to return the payload.

8. Protocol processing
=======================

Executing a protocol requires:

 * A session

 * Protocol name (may be zero bytes)

 * (Optional) Pre-knowledge of the remote party's static and/or ephemeral public keys

 * (Optional) A static key pair

 * (Optional) Pre-shared symmetric key

 * A pattern

First `InitializeSession()` is called.  Then `MixKey(name)` is called.

If the party has a static key pair, then `SetStaticKeyPair()` is called to set
it into the session.  

Next any pre-messages in the pattern are processed.  This has no effect except
performing more `MixHash()` calls based on the party's pre-knowledge.

If the party has a pre-shared symmetric key then `MixKey()` is called to mix it
into the kernel.

Following this the parties read and write handshake messages.  After every
handshake message `MixHash(payload)` is called, except for the last handshake
message.  After the last handshake message `ClearHash()` is called.

9. Handshake patterns
======================

The following patterns represent the mainstream use of Noise, and can be used
to construct a wide range of protocols.  Of course, other patterns can be
defined in other documents.

Each pattern is given a name, and then described via a sequence of
descriptors.  Descriptors with right-pointing arrows are for messages created
and sent by the protocol initiator; with left-pointing arrows are for messages
sent by the responder.

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These messages aren't sent as part of the protocol proper, but are only used for
their side-effect of calling `MixHash()`.



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

The following 16 "Handshake" patterns represent protocols where the initiator and
responder exchange messages to agree on a shared key.

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

 * **`DH(privkey, pubkey)`**: Curve25519 (Noise255) or Goldilocks (Noise448).
 
 * **`ENCRYPT(k, n, ad, plainttext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is formed by encoding
 32 bits of zeros followed by little-endian encoding of `n`.  (Earlier
 implementations of ChaCha20 used a 64-bit nonce, in which case it's compatible
 to encode `n` directly into the ChaCha20 nonce).

 * **`GETKEY(k, n)`**:  The first 32 bytes output from the ChaCha20 block
   function from RFC 7539 with key `k`, nonce `n` encoded as for `ENCRYPT()`,
   and the block count set to 1.  This is the same as calling `ENCRYPT()` on a
   plaintext consisting of 32 bytes of zeros and taking the first 32 bytes. 

 * **`KDF(kdf_key, input)`:** `HMAC-SHA2-256(kdf_key, input)`.  
 

10.2. AES256-GCM ciphersuites
-----------------------------

These ciphersuites are named Noise255/AES256-GCM and Noise448/AES256-GCM.  The
`DH()` and `KDF()` functions are the same as above.

 * **`klen`** = 32

 * **`DH(privkey, pubkey)`**: Curve25519 (Noise255) or Goldilocks (Noise448).

 * **`ENCRYPT(k, n, ad, plainttext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D.  The 96-bit nonce is formed by encoding 32
 bits of zeros followed by little-endian encoding of `n`.
 
 * **`GETKEY(k, n)`**: is defined by encoding the 96-bit nonce from above into the
 first 96 bits of two 16-byte blocks `B1` and `B2`.  The final 4 bytes of `B1`
 are set to (0, 0, 0, 2).  The final 4 bytes of `B2` are set to (0, 0, 0, 3).
 `B1` and `B2` are both encrypted with AES256 and key `k`, and the resulting
 ciphertexts `C1` and `C2` are concatenated into the final 32-byte output.  This is
 the same as calling `ENCRYPT()` on a plaintext consisting of 32 bytes of zeros
 and taking the first 32 bytes.


11. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be
catastrophic.  Implementations must carefully follow the rules for incrementing
nonces.   `SetNonce()` should only be called with extreme caution.

To avoid catastrophic key reuse, every party in a Noise protocol should send a
fresh ephemeral public key and performs a DH with it prior to sending any
encrypted data.  All patterns in Section 9 adhere to this rule.  

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
 * SHA2-256 processes smaller input blocks than SHA2-512 (64 bytes vs 128 bytes), avoiding unnecessary calculation when processing smaller inputs

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


