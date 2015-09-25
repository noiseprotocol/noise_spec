
Noise v0 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-09-21
 * **Revision:** 06 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key agreement.
Noise can describe protocols that consist of a single message as well as
interactive protocols.

2. Overview
============

A Noise protocol begins with a **handshake phase** where two parties send
**handshake messages**.  During the handshake phase the two parties perform a
DH-based key agreement to agree on a shared secret key.  After the handshake
phase each party can send **transport messages** encrypted with the shared key.

The Noise framework can support any DH-based handshake where each party has a
long-term **static key pair** and/or an **ephemeral key pair**.  The handshake
is described by **descriptors** and **patterns**.  A **descriptor** specifies
the DH public keys that comprise a handshake message, and the DH operations
that are performed when sending or receiving that message.  A **pattern**
specifies the sequence of descriptors that comprise a handshake.

A handshake pattern can be instantiated by **DH parameters** and **symmetric
crypto parameters** to give a concrete protocol.  An application using Noise
must handle some **application responsibilities** on its own, such as indicating
message lengths, and specifying a format for payload data.

3.  Message format
===================

All Noise messages are less than or equal to 65535 bytes in length, and can be
processed without parsing, since there are no type or length fields within the
message.  In some contexts a Noise message might be preceded by some type or
length fields but that's an **application responsibility** - see Section 10. 

A handshake message begins with a sequence of one or more DH public keys.
Whether each public key is ephemeral or static is specified by the message's
descriptor.  Public keys may be encrypted to provide identity hiding.  

Following the public keys will be a **payload** which could be used to convey
certificates or other handshake data, and which may also be encrypted.
Encryption of public keys and payloads will occur once a shared secret key has
been established.  Zero-length payloads are allowed and will result in 16-byte
payload ciphertexts, since encryption adds a 16-byte **authentication tag** to
each ciphertext.

A transport message consists solely of an encrypted payload. 

4.  Crypto algorithms
======================

A Noise protocol depends on **DH parameters** and **symmetric crypto
parameters**.  The DH parameters specify the Diffie-Hellman function, which will
typically be ECDH over some elliptic curve.  The symmetric crypto parameters
specify symmetric crypto algorithms (cipher and hash function).

During a Noise handshake, the outputs from DH calculations will be sequentially
mixed into a secret key variable (**`k`**).  This key is used to encrypt static
public keys and handshake payloads.  Public keys and handshake payloads will be
mixed into a hash variable (**`h`**).  The `h` variable will be authenticated
with every handshake ciphertext, to ensure these ciphertexts are bound to
earlier messages.

To handle `k` and its associated **nonce** `n` we introduce the notion of a
**`CipherState`** which contains `k` and `n` variables.  This object has
associated functions (or "methods") for performing encryption and decryption
using its variables.

To handle mixing inputs into `k` and `h` we introduce a
**`SymmetricHandshakeState`** which extends a `CipherState` with an `h`
variable.  An implementation will create a `SymmetricHandshakeState` to handle a
single Noise handshake, and can delete it once the handshake is finished.  

A `SymmetricHandshakeState` supports initializing `h` with a **handshake name**
to reduce risks from key reuse.  It also supports "splitting" into two
`CipherState` objects which are used for transport messages once the handshake
is complete.

The below sections describe these concepts in more detail.


4.1. DH parameters and symmetric crypto parameters
------------------------------------------

Noise depends on the following **DH parameters**:

 * **`DHLEN`** = A constant specifying the size of public keys in bytes.
 
 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes.  If the public key is invalid the output of this calculation
 is up to the implementation but must not leak information about the private
 key.  Implementations are also allowed to abort on receiving or processing an
 invalid public key.

Noise depends on the following **symmetric crypto parameters**:

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts `plaintext` using the cipher
 key `k` of 256 bits and a 64-bit unsigned integer nonce `n` which must be
 unique for the key `k`.  Encryption must be done with an "AEAD" encryption
 mode with the associated data `ad` and must add a 128-bit authentication tag
 to the end of the message.  This must be a deterministic function (i.e.  it
 shall not add a random IV; this ensures the `GETKEY()` function is
 deterministic).

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using a cipher
 key `k` of 256 bits, a 64-bit unsigned integer nonce `n`, and associated
 data `ad`.  If the authentication fails an error is signaled to the caller.

 * **`GETKEY(k, n)`**:  Calls the `ENCRYPT()` function with cipher key `k`,
 nonce `n`, and zero-length `ad` to encrypt a block of 256 zero bits.  Returns
 the first 256 bits from the encrypted output.  This function can usually be
 implemented more efficiently than by calling `ENCRYPT` (e.g.  by skipping the
 authentication tag calculation).

 * **`HASH(data)`**: Hashes some arbitrary-length data with a
 cryptographically-secure collision-resistant hash function and returns an
 output of 256 bits. `SHA2-256` is an example hash function.

 * **`HMAC-HASH(key, data)`**: Calculates `HMAC` using the above hash function.
 Takes a 256-bit key, variable-length data, and produces a 256-bit output.


4.2. The  `CipherState` object 
-------------------------------

A `CipherState` can encrypt and decrypt data based on its `k` and `n` variables:

 * **`k`**: A symmetric key of 256 bits for the cipher algorithm specified in
 the symmetric crypto parameters.

 * **`n`**: A 64-bit unsigned integer nonce.

A `CipherState` responds to the following methods.  The `++` post-increment
operator applied to `n` means "use the current `n` value, then increment it".

 * **`EncryptAndIncrement(ad, plaintext)`**:  Returns `ENCRYPT(k, n++, ad,
 plaintext)`.

 * **`DecryptAndIncrement(ad, ciphertext)`**:  Returns `DECRYPT(k, n++, ad,
 ciphertext)`.  If an authentication failure occurs the error is signaled to the
 caller.

4.3. The `SymmetricHandshakeState` object
-----------------------------------------

A `SymmetricHandshakeState` object extends a `CipherState` with the following
variables:

 * **`has_key`**: A boolean that records whether key `k` is a secret value.

 * **`h`**: A 256-bit hash output.  This is used as "associated data" for
 encryption.  

A `SymmetricHandshakeState` responds to the following methods. The `||` operator
indicates concatentation of byte sequences.  
 
 * **`InitializeSymmetric(handshake_name)`**:  Takes an arbitrary-length
 `handshake_name`.  Sets `k` to all zeros, `n = 0` and `has_key = False`.  If
 `handshake_name` is less than or equal to 32 bytes in length, sets `h` equal to
 `handshake_name` with zero bytes appended to make 32 bytes.  Otherwise sets `h
 = HASH(handshake_name)`.

 * **`MixKey(data)`**:  Sets `k = HMAC-HASH(GETKEY(k, n), data)`.  Sets `n =
  0`.  Sets `has_key = True`.  This will be called to mix DH outputs into the
  key.

 * **`EncryptAndHash(plaintext)`**: If `has_key == True` sets `ciphertext =
 EncryptAndIncrement(h, plaintext)`, sets `h = HASH(h || ciphertext)`, and
 returns `ciphertext`.  Otherwise sets `h = HASH(h || plaintext)` and returns
 `plaintext`.

 * **`DecryptAndHash(data)`**: If `has_key == True` sets `plaintext =
 DecryptAndIncrement(h, data)`, sets `h = HASH(h || data)`, and returns
 `plaintext`.  Otherwise sets `h = HASH(h || data)` and returns `data`.

 * **`Split()`**:  Creates two child `CipherState` objects by calling `GETKEY(k,
 n++)` to get the first child's `k`, then calling `GETKEY(k, n++)` to get the
 second child's `k`.  The children have `n` set to zero.  The two children are
 returned.  This will be called at the end of a handshake to get separate
 `CipherState` objects for the send and receive directions.


5.  The handshake algorithm
============================

A descriptor for a handshake message is some sequence of **tokens** from "e, s,
dhee, dhes, dhse, dhss".  To send (or receive) a handshake message you iterate
through the tokens that comprise the message's descriptor.  For each token you
write (or read) the public key it specifies, or perform the DH operation it
specifies.  While doing this you call `MixKey()` on DH outputs and `MixHash()`
on public keys and payloads.

To provide a rigorous description we introduce the notion of a `HandshakeState`
object.  A `HandshakeState` extends a `SymmetricHandshakeState` with DH
variables.  

To execute a Noise protocol you `Initialize()` a `HandshakeState`, then call
`MixHash()` for any public keys that were exchanged prior to the
handshake (see Section 6).  Then you call `WriteHandshakeMessage()` and
`ReadHandshakeMessage()` using successive descriptors from a handshake pattern.
If a decryption error occurs the handshake has failed and the `HandshakeState`
is deleted without sending further messages.

Processing the final handshake message returns two `CipherState` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  At that point the `HandshakeState`
may be deleted.  Transport messages are then encrypted and decrypted by calling
`EncryptAndIncrement()` and `DecryptAndIncrement()` on the relevant
`CipherState` with zero-length associated data.


5.1. The `HandshakeState` object
---------------------------------

A `HandshakeState` contain the following variables:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 


A `HandshakeState` responds to the following methods:

 * **`Initialize(handshake_name, new_s, new_e, new_rs, new_re)`**: Takes a
 `handshake_name` (see Section 9).  Also takes a set of DH keypairs and public
 keys for initializing local variables, any of which may be empty.
 
   * Calls `InitializeSymmetric(handshake_name)`.
   
   * Sets `s`, `e`, `rs`, and `re` to the corresponding arguments.

 * **`WriteHandshakeMessage(buffer, descriptor, final, payload)`**: Takes an
 empty byte buffer, a descriptor which is some sequence using tokens from "e, s,
 dhee, dhes, dhse, dhss", a `final` boolean which indicates whether this is the
 last handshake message, and a `payload` (which may be zero-length).
 
    * Processes each token in the descriptor sequentially:

      * For "e":  Sets `e = GENERATE_KEYPAIR()`.  Appends
      `EncryptAndHash(e.public_key)` to the buffer.

      * For "s":  Appends `EncryptAndHash(s.public_key)` to the buffer.
      
      * For "dh*xy*":  Calls `MixKey(DH(x, ry))`.

    * Appends `EncryptAndHash(payload)` to the buffer.  
    
    * If `final == True` returns two new `CipherState` objects by calling
    `Split()`.

 * **`ReadHandshakeMessage(buffer, descriptor, final)`**: Takes a byte buffer
 containing a message, a descriptor, and a `final` boolean which indicates
 whether this is the last handshake message.  Returns a payload.  If a
 decryption error occurs the error is signaled to the caller.

    * Processes each token in the descriptor sequentially:

      * For "e": Sets `data` to the next `DHLEN + 16` bytes of buffer if `has_key ==
      True`, or to the next `DHLEN` bytes otherwise.  Sets `re` to
      `DecryptAndHash(data)`.

      * For "s": Sets `data` to the next `DHLEN + 16` bytes of buffer if `has_key ==
      True`, or to the next `DHLEN` bytes otherwise.  Sets `rs` to
      `DecryptAndHash(data)`.
      
      * For "dh*xy*":  Calls `MixKey(DH(y, rx))`.

    * Sets `payload = DecryptAndHash(buffer)`.
  
    * If `final == True` returns the `payload` and two new `CipherState` objects
    created by calling `Split()`.  Otherwise returns the `payload`.
    
6. Handshake patterns 
======================

A descriptor is some sequence of tokens from "e, s, dhee, dhes, dhse, dhss".  A
pattern is a sequence of descriptors. The first descriptor describes the first
message sent from the initiator to the responder; the next descriptor describes
the response message, and so on.  All messsages described by the pattern must be
sent in order.  

The following pattern describes an unauthenticated DH handshake:

      -> e
      <- e, dhee

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These indicate an exchange of public keys was somehow performed prior to the
handshake, so these key pairs and public keys should be inputs to
`Initialize()`.  After `Initialize()` is called, `MixHash()` is called on any
pre-message public keys in the order they are listed.

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral:

      <- s
      ------
      -> e, dhes 
      <- e, dhee

6.1. One-way patterns
----------------------

The following patterns represent "one-way" messages from a sender to a
recipient.

     N  = no static key for sender
     S  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    Noise_N:
      <- s
      ------
      -> e, dhes

    Noise_S:
      <- s
      -> s
      ------
      -> e, dhes, dhss

    Noise_X:
      <- s
      ------
      -> e, dhes, s, dhss

6.2. Interactive patterns 
--------------------------

The following 16 patterns represent protocols where the initiator and responder
exchange messages to agree on a shared key.

     N_ = no static key for initiator
     S_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder
     I_ = static key for inititiator immediately transmitted to responder
 
     _N = no static key for responder
     _S = static key for responder known to initiator
     _E = static key plus a semi-ephemeral key for responder known to initiator
     _X = static key for responder transmitted to initiator


    Noise_NN:                        Noise_SN:                 
      -> e                             -> s                       
      <- e, dhee                       ------                     
                                       -> e                       
                                       <- e, dhee, dhes           
                                             
    Noise_NS:                        Noise_SS:                 
      <- s                             <- s                       
      ------                           -> s                       
      -> e, dhes                       ------                     
      <- e, dhee                       -> e, dhes, dhss           
                                       <- e, dhee, dhes           
                                              
    Noise_NE:                        Noise_SE:                 
      <- s, e                          <- s, e                    
      ------                           -> s                       
      -> e, dhee, dhes                 ------                     
      <- e, dhee                       -> e, dhee, dhes, dhse     
                                       <- e, dhee, dhes           
                                                                     
    Noise_NX:                        Noise_SX:                 
      -> e                             -> s                       
      <- e, dhee, s, dhse              ------                     
                                       -> e                       
                                       <- e, dhee, dhes, s, dhse  
                            

    Noise_XN:                        Noise_IN:                   
      -> e                             -> e, s                      
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    Noise_XS:                        Noise_IS:                   
      <- s                             <- s                         
      ------                           ------                       
      -> e, dhes                       -> e, dhes, s, dhss          
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    Noise_XE:                        Noise_IE:                   
      <- s, e                          <- s, e                      
      ------                           ------                       
      -> e, dhee, dhes                 -> e, dhee, dhes, s, dhse    
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                       
    Noise_XX:                        Noise_IX:                  
      -> e                             -> e, s                     
      <- e, dhee, s, dhse              <- e, dhee, dhes, dhse                                
      -> s, dhse

7. Handshake re-initialization and "Noise Pipes"
===============================================

A protocol may support handshake re-initialization.  In this case, the recipient
of a handshake message must also receive some indication whether this is the
next message in the current handshake, or whether to re-initialize the
`HandshakeState` and do something different.

By way of example, this section defines the **Noise Pipe** protocol.  This
protocol uses `Noise_XX` for a full handshake but also provides an abbreviated
handshake via `Noise_IS`.  The abbreviated handshake lets the initiator send
some encrypted data in the first message if the initiator has pre-knowledge of
the responder's static public key.  

If the responder fails to decrypt the first `Noise_IS` message (perhaps due to
changing her static key), she will use the `Noise_XXfallback` pattern to "fall
back" to a handshake identical to `Noise_XX` except re-using the initiator's
ephemeral public key as a pre-message.

Below are the three patterns used for Noise Pipes:

    Noise_XX:  
      -> e
      <- e, dhee, s, dhse  
      -> s, dhse

    Noise_IS:                   
      <- s                         
      ------
      -> e, dhes, s, dhss          
      <- e, dhee, dhes             
                                        
    Noise_XXfallback:                   
      -> e
      ------
      <- e, dhee, s, dhse
      -> s, dhse

Note that encrypted data sent in the first `Noise_IS` message is susceptible to
replay attacks.  Also, if the responder's static private key is compromised,
initial messages can be decrypted and/or forged.

To distinguish these patterns, each handshake message will be preceded by a
`type` byte:

 * If `type == 0` in the initiator's first message then the initiator is performing
 a `Noise_XX` handshake.

 * If `type == 1` in the initiator's first message then the initiator
 is performing a `Noise_IS` handshake.

 * If `type == 1` in the responder's first `Noise_IS` response then the
 responder failed to authenticate the initiator's `Noise_IS` message and is
 performing a `Noise_XXfallback` handshake, using the initiator's ephemeral
 public key as a pre-message.

 * In all other cases, `type` will be 0.

8. DH parameters and symmetric crypto parameters 
===============================

8.1. The 25519 DH parameters
----------------------------

 * **`DHLEN`** = 32
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 function.  If the function
 detects an invalid public key, the output may be set to all zeros or any other
 value that doesn't leak information about the private key.  Implementations are
 also allowed to abort on receiving or processing an invalid public key.

8.2. The 448 DH parameters
--------------------------

 * **`DHLEN`** = 56
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve448 function.  If the function
 detects an invalid public key, the output may be set to all zeros or any other
 value that doesn't leak information about the private key.  Implementations are
 also allowed to abort on receiving or processing an invalid public key.

8.3. The ChaChaPoly symmetric crypto parameters 
------------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is formed by encoding
 32 bits of zeros followed by little-endian encoding of `n`.  (Earlier
 implementations of ChaCha20 used a 64-bit nonce, in which case it's compatible
 to encode `n` directly into the ChaCha20 nonce).

 * **`GETKEY(k, n)`**:  Returns the first 32 bytes from calling `ENCRYPT(k, n,
 ...)` with zero-length `ad` and 32 bytes of zeros for `plaintext`.  A more
 optimized implementation can return the first 32 bytes output from the ChaCha20
 block function from RFC 7539 with key `k`, nonce `n` encoded as for
 `ENCRYPT()`, and the block count set to 1.  

 * **`HASH(input)`**: `SHA2-256(input)` 

8.4. The AESGCM symmetric crypto parameters 
---------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D with 128-bit tags.  The 96-bit nonce is formed
 by encoding 32 bits of zeros followed by big-endian encoding of `n`.
 
 * **`GETKEY(k, n)`**: Returns the first 32 bytes from calling `ENCRYPT(k, n,
 ...)` with zero-length `ad` and 32 bytes of zeros for `plaintext`.  A more
 optimized implementation can return 32 bytes from concatenating two encryption
 calls to the AES256 block cipher using key `k`.  The 128-bit block cipher
 inputs are defined by encoding `n` into a 96-bit value as for `ENCRYPT()`, then
 setting this as the first 96 bits of two 128-bit blocks `B1` and `B2`.  The
 final 4 bytes of `B1` are set to (0, 0, 0, 2).  The final 4 bytes of `B2` are
 set to (0, 0, 0, 3).  `B1` and `B2` are both encrypted with AES256 and key `k`,
 and the resulting ciphertexts `C1` and `C2` are concatenated into the 32-byte
 output.

 * **`HASH(input)`**: `SHA2-256(input)` 


9. Handshake names 
=========================

To produce a **handshake name** for `Initialize()` you add the DH parameter and
symmetric crypto parameter names to the handshake pattern name.  For example: 

 * `Noise_N_25519_ChaChaPoly`
 
 * `Noise_XXfallback_25519_AESGCM`
 
 * `Noise_IS_448_AESGCM`

10. Application responsibilities
================================

An application built on Noise must consider several issues:

 * **Extensibility**:  Applications are recommended to use an extensible data
 format for the payloads of all messages (e.g. JSON, Protocol Buffers) so that
 fields can be added in the future which are ignored by older implementations.

 * **Padding**:  Applications are recommended to use a data format for the
 payloads of all encrypted messages that allows padding, so that payload lengths
 can be padded to not leak information about message sizes.  Using an extensible
 data format, per the previous bullet, will typically suffice.

 * **Termination**: Applications must consider that a sequence of Noise
 transport messages could be truncated by an attacker.  Applications should
 include explicit length fields or termination signals inside of transport
 payloads to signal the end of a stream of transport messages. 

 * **Length fields**:  Applications must handle any framing or additional length
 fields for Noise messages, considering that a Noise message may be up to 65535
 bytes in length.  Applications are recommended to add a 16-bit big-endian
 length field prior to each message.

 * **Type fields**:  Applications are recommended to include a single-byte type
 field prior to each Noise handshake message (and prior to the length field, if
 one is included).  This allows extending the handshake with handshake
 re-initialization or other alternative messages in the future.


11. Security considerations
===========================

This section collects various security considerations:

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key `k`
 for encryption would be catastrophic.  Implementations must carefully follow
 the rules for incrementing nonces.   

 * **Fresh ephemerals**:  Every party in a Noise protocol should send a new
 ephemeral public key and perform a DH with it prior to sending any encrypted
 data.  Otherwise replay of a handshake message could trigger a catastrophic key
 reuse. This is one rationale behind the patterns in Section 6.

 * **Handshake names**:  The handshake name used with `Initialize()` must
 uniquely identify a single combination of handshake pattern, DH parameters, and
 symmetric crypto parameters for every key it's used with (whether ephemeral key
 pair or static key pair).  If the same secret key was used in
 different protocol executions with the same handshake name but a different
 sequence of cryptographic operations then bad interactions could occur between
 the executions.

 * **Channel binding**:  Depending on the DH parameters, it might be possible
 for a malicious party to engage in multiple sessions that derive the same
 shared secret key (e.g. if setting her public keys to invalid values causes DH
 outputs of zero).  If a higher-level protocol wants a unique "channel binding"
 value for referring to a Noise session it should use `h`, not `k`.

12. Rationale
=============

This section collects various design rationale:

Noise messages are <= 65535 bytes because:

 * This allows safe streaming decryption, and random access decryption of large files.
 * This simplifies testing and reduces likelihood of memory or overflow errors in handling large messages
 * This restricts length fields to a standard size of 16 bits, aiding interop 
 * The overhead of larger standard length fields (e.g. 32 or 64 bits) might cost something for small messages, but the overhead of smaller length fields is insignificant for large messages.

Nonces are 64 bits in length because:

 * Some ciphers (e.g. Salsa20) only have 64 bit nonces.
 * 64 bit nonces were used in the initial specification and implementations of ChaCha20, so Noise nonces can be used with these implementations.
 * 64 bits allows the entire nonce to be treated as an integer and incremented.
 * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if random nonces are acceptable.

The default symmetric crypto parameters use SHA2-256 because:

 * SHA2 is widely available
 * SHA2-256 requires less state than SHA2-512 and produces a sufficient-sized output (32 bytes).
 * SHA2-256 processes smaller input blocks than SHA2-512 (64 bytes vs 128 bytes), avoiding unnecessary calculation when processing smaller inputs.

The cipher key must be 256 bits because:

 * The cipher key accumulates the DH output, so collision-resistance is desirable.

The authentication tag is 128 bits because:

 * Some algorithms (e.g. GCM) lose more security than an ideal MAC when truncated.
 * Noise may be used in a wide variety of contexts, including where attackers can receive rapid feedback on whether MAC guesses are correct.
 * A single fixed length is simpler than supporting variable-length tags.

Big-endian is preferred because:

 * While it's true that bignum libraries, Curve25519, Curve448, and
 ChaCha20/Poly1305 use little-endian, these will likely be handled by
 specialized libraries.
 * Some ciphers use big-endian internally (e.g. GCM, SHA2).
 * The Noise length fields are likely to be handled by
 parsing code where big-endian "network byte order" is 
 traditional.

The `MixKey()` design uses `HMAC-HASH(GETKEY(), ...)` because:

 * `HMAC-HASH()` uses the previous key to extract entropy from subsequent DH
 values.  This use of `HMAC` as a keyed extractor is similar to HKDF, so if `k`
 is secret this can leverage the `HKDF` analysis instead of the Random Oracle
 Model.  It also ensures that the new `k` produced by `MixKey()` is a PRF from
 the old `k`, so the old `k` is not exposed, and the new `k` is
 indistinguishable from random without knowledge of old `k`.


13. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

14. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Feedback on the spec came from: Moxie Marlinspike, Jason Donenfeld, Tiffany
Bennett, Jonathan Rudenberg, Stephen Touset, and Tony Arcieri.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


