
Noise v0 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-09-17
 * **Revision:** 04 (work in progress)
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

Each handshake message consists of a sequence of one or more DH public keys,
followed by a payload which may contain arbitrary data (e.g. certificates).
Some of the public keys and payloads may be encrypted.

A handshake pattern can be instantiated by **DH parameters** and **cipher
parameters** to give a concrete protocol.  An application using Noise must
handle several **application responsibilities** on its own, such as indicating
message lengths, or adding padding and extensibility into the payload.

3.  Message format
===================

All Noise messages are less than or equal to 65535 bytes in length, and can be
processed without parsing (there are no length fields or type fields within the
message). 

A handshake message begins with a sequence of one or more DH public keys which
are being sent to the other party.  Whether each public key is ephemeral or
static is specified by the message's descriptor.

Ephemeral public keys are sent in the clear.  Static public keys may be
encrypted (to provide identity hiding).  Following the public keys will be a
payload, which may also be encrypted.  Encryption of static public keys and
payloads will occur if a shared secret key has been established, either from a
pre-shared key, or from the output of handshake DH calculations.  

Transport messages consist solely of an encrypted payload. 

4.  Crypto algorithms and `cipherstate` objects
================================================

A Noise protocol depends on **DH parameters** and **cipher parameters**.  The DH
parameters specify the Diffie-Hellman function, which will typically be ECDH
over some elliptic curve.  The cipher parameters specify the symmetric crypto
algorithms.

During a Noise handshake, the output from successive DH calculations will be
mixed into a secret key (**`k`**).  This secret key is used to encrypt static
public keys and handshake payloads, and will also be used to derive the keys
that encrypt transport messages.  

During a Noise handshake, when static public keys and handshake payloads are
transmitted their plaintext will be mixed into a hash value (**`h`**).  This
value will be authenticated along with every handshake ciphertext, to ensure
that all handshake ciphertexts are bound to all important context from earlier
messages.

To handle `k` and `h` we introduce the notion of a **`cipherstate`** which
contains `k` and `h` variables and provides methods for working with them.  A
`cipherstate` supports mixing inputs into the `k` and `h` variables, performing
encryption and decryption, and "splitting" into two cipherstates which can be
used for independent sequences of transport messages.

The below sections describe the DH parameters, cipher parameters, and
`cipherstate` notion in more detail.


3.1. DH parameters and cipher parameters
------------------------------------------

Noise depends on the following **DH parameters**:

 * **`DHLEN`** = A constant specifying the size of public keys in bytes.
 
 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

Noise depends on the following **cipher parameters**:

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
 nonce `n`, and empty `ad` to encrypt a block of 256 zero bits.  Returns the
 first 256 bits from the encrypted output.  This function can usually be
 implemented more efficiently than by calling `ENCRYPT` (e.g.  by skipping the
 authentication tag calculation).

 * **`KDF(key, input)`**: Takes a `key` of 256 bits and some input data and
 returns a 256-bit output.  This function should implement a cryptographic "PRF"
 keyed by `key`.  This function should also be a collision-resistant hash
 function given a known `key`.  `HMAC-SHA2-256` is an example KDF.

 * **`HASH(data)`**: Hashes some input data and returns a collision-resistant
 hash output of 256 bits. `SHA2-256` is an example hash function.

3.2. The  `cipherstate` object 
-------------------------------

A `cipherstate` can mix inputs into its internal state, and can encrypt and
decrypt data based on its internal state.  A `cipherstate` contains the
following variables:

 * **`k`**: A symmetric key of 256 bits for the cipher algorithm specified in
 the cipher parameters.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with `k`
 for encryption.

 * **`h`**: Either empty or 256 bits containing a hash output.  This is used as
 "associated data" for encryption.
 
A `cipherstate` responds to the following methods.  The `++` post-increment
operator applied to `n` means "use the current value, then increment it".  The
`||` operator indicates concatentation of byte sequences.

 * **`Initialize()`**:  Sets `k` to all zeros, `n` to zero, and `h` to all zeros.
 
 * **`MixKey(data)`**:  Sets `k` to `KDF(GETKEY(k, n++), data)`.  This will be
 called to mix DH outputs into the key.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  This will be called to
 mix static public keys and handshake payloads into the hash value.

 * **`Split()`**:  Creates two new child `cipherstate` objects by calling
 `GETKEY(K, n++)` to get the first child's `k`, then calling `GETKEY(k, n++)` to
 get the second child's `k`.  The children have `n` set to zero and `h` set to
 empty (i.e.  zero-length). The two children are returned.  This will be called
 at the end of a handshake to yield separate `cipherstates` for the send and
 receive directions.

 * **`Encrypt(plaintext)`**:  Returns `ENCRYPT(k, n++, h, plaintext)`.

 * **`Decrypt(ciphertext)`**:  Returns `DECRYPT(k, n++, h, ciphertext)`.  If an
 authentication failure occurs the error is signaled to the caller.

4.  The handshake algorithm and `handshakestate` objects
=========================================================

To execute a Noise handshake, two parties take turns sending and receiving
messages.  Each message and its processing is specified by a handshake
descriptor.

To send (or receive) a message you iterate through the tokens that comprise a
descriptor, writing (or reading) the public keys it specifies, performing the DH
operations it specifies, and calling `cipherstate.MixKey()` on DH outputs and
`cipherstate.MixHash()` on static public keys and payloads.

To provide a rigorous description we introduce the notion of a `handshakestate`
object.  A `handshakestate` contains DH variables and a `cipherstate`.  

To execute a Noise protocol you `Initialize()` a `handshakestate` object, then
call `WriteHandshakeMessage()` and `ReadHandshakeMessage()` using successive
descriptors from a handshake pattern until the handshake is complete.  If a
decryption error occurs the handshake has failed and the `handshakestate` is
deleted without sending further messages.

Processing the final handshake message returns two `cipherstate` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  Transport messages can be encrypted
and decrypted by calling `cipherstate.Encrypt()` and `cipherstate.Decrypt()`.


3.4. The `handshakestate` object
---------------------------------

A `handshakestate` contain the following variables:

 * **`cipherstate`**: An object that provides symmetric crypto.

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

 * **`has_key`**: Boolean that records whether the `cipherstate` has a secret
 key.

A `handshakestate` responds to the following methods:

 * **`Initialize(name, preshared_key, static_keypair,
 preshared_ephemeral_keypair)`**: Takes a concrete handshake `name` (see Section
 7) and `preshared_key` which are both variable-length byte sequences (the
 `preshared_key` may be zero-length).  Also takes optional static and
 "pre-shared ephemeral" keypairs.
 
   * Calls `cipherstate.Initialize()`.
   
   * Calls `cipherstate.MixKey(name || 0x00 || preshared_key)`.

   * If `preshared_key` isn't empty then sets `has_key` to `True`, otherwise
   sets it to `False`.
  
   * Sets `s` to `static_keypair` (which may be empty).

   * Sets `e` to `preshared_ephemeral_keypair` (which may be empty).

   * Sets `rs` and `re` to empty.

 * **`WriteHandshakeMessage(buffer, descriptor, final, payload)`**: Takes an
 empty byte buffer, a descriptor which is some sequence of the tokens from "e,
 s, dhee, dhes, dhse, dhss", a `final` boolean which indicates whether this is
 the last handshake message, and a `payload` (which may be zero-length).
 
    * Processes each token in the descriptor sequentially:
      * For "e":  Sets `e = GENERATE_KEYPAIR()` and appends the public key to the buffer.  

      * For "s":  If `s` is empty copies `e` to `s` (see "dummy static" public
      keys in Section 4).  If `has_key == True` appends
      `cipherstate.Encrypt(s.public_key)` to buffer, otherwise appends
      `s.public_key`.  Finally calls `cipherstate.MixHash(s.public_key)`.

      * For "dh*xy*" calls `cipherstate.MixKey(DH(x, ry))` and sets `has_key` to
      True.

    * If `has_key == True` appends `cipherstate.Encrypt(payload)` to buffer,
    otherwise appends `payload`.  
    
    * If `final == False` calls `cipherstate.MixHash(payload)`, otherwise
    returns two new `cipherstate` objects by calling `cipherstate.Split()`.

 * **`ReadHandshakeMessage(buffer, descriptor, final)`**: Takes a byte buffer
 containing a message, a descriptor, and a `final` boolean which indicates
 whether this is the last handshake message, and returns a payload.  If a
 decryption error occurs the error is signaled to the caller.

    * Processes each token in the descriptor sequentially:
      * For "e": Sets `re` to the next `DHLEN` bytes from `buffer`.  

      * For "s": If `has_key == True` sets `rs` to `cipherstate.Decrypt()` on
      the next `DHLEN + 16` bytes, otherwise sets `rs` to the next `DHLEN`
      bytes.  Finally calls `cipherstate.MixHash(rs)`.
      
      * For "dh*xy*" calls `cipherstate.MixKey(DH(y, rx))` and sets `has_key` to
      True.

    * If `has_key == True` sets `payload = cipherstate.Decrypt()` on the rest of
    the buffer, otherwise sets `payload` to the rest of the buffer.
  
    * If `final == False` calls `cipherstate.MixHash(payload)` and returns
    `payload`, otherwise returns `payload` and two new `cipherstate` objects by
    calling `cipherstate.Split()`.
    
4. Handshake patterns 
======================

A descriptor is some sequence of the tokens from "e, s, dhee, dhes, dhse,
dhss".  A pattern is a sequence of descriptors. The first descriptor describes
the first message sent from the initiator to the responder; the next descriptor
describes the response message, and so on.  All messsages described by the
pattern must be sent in order.  

The following pattern describes an unauthenticated DH handshake:

      -> e
      <- e, dhee

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These messages are used with `WriteHandshakeMessage()` and
`ReadHandshakeMessage()` but aren't actually sent.  They're only used for their
side-effect of calling `MixHash()` and initializing `rs` and `re`.  

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral:

      <- s
      ------
      -> e, dhes 
      <- e, dhee

Patterns where one party sends their static public key allow that party to opt
out of authenticating themselves.  If that party sets their static public key
equal to their ephemeral public key (a "dummy static" public key), this signals
to the other party that a distinct static public key does not exist.

4.1. One-way patterns
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

4.2. Interactive patterns 
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

5. Pattern re-initialization and "Noise Pipes"
===============================================

A handshake may support pattern re-initialization.  In this case, the recipient
of a handshake message must also receive some indication whether this is the
next message in the current pattern, or whether to re-initialize the
`HandshakeState` and execute a different pattern.

By way of example, this section defines the `Noise_Pipe` protocol.  This
protocol uses `Noise_XX` for a full handshake but also provides an abbreviated
or "zero-round-trip" handshake via `Noise_IS` if the initiator has pre-knowledge
of the responder's static public key.  If the responder fails to decrypt the
first `Noise_IS` message (perhaps due to changing her static key), she will use
the `Noise_XXfallback` pattern to "fall back" to `Noise_XX` while re-using the
initiator's ephemeral public key.

Encrypted data sent in the first `Noise_IS` message is susceptible to replay
attacks, and also loses forward security and authentication if the responder's
static private key is compromised. So a 0-RTT encrypted payload should only be
used when this is acceptable.

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

To distinguish these patterns, each handshake message will be preceded by a `type` byte:

 * If `type == 0` in the initiator's first message then the initiator is performing
 a `Noise_XX` handshake.

 * If `type == 1` in the initiator's first message then the initiator
 is performing a `Noise_IS` handshake.

 * If `type == 1` in the responder's first `Noise_IS` response then the
 responder failed to authenticate the initiator's `Noise_IS` message and is
 performing a `Noise_XXfallback` handshake, using the initiator's ephemeral
 public key as a pre-message.

 * In all other cases, `type` will be 0.

6. DH parameters and cipher parameters
===============================

6.1. The 25519 DH parameters
----------------------------

 * **`DHLEN`** = 32
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 function.

6.2. The 448 DH parameters
--------------------------

 * **`DHLEN`** = 56
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve448 function.

6.3. The ChaChaPoly cipher parameters
------------------------------

 * **`ENCRYPT(k, n, ad, plainttext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is formed by encoding
 32 bits of zeros followed by little-endian encoding of `n`.  (Earlier
 implementations of ChaCha20 used a 64-bit nonce, in which case it's compatible
 to encode `n` directly into the ChaCha20 nonce).

 * **`GETKEY(k, n)`**:  Returns the first 32 bytes output from the ChaCha20
 block function from RFC 7539 with key `k`, nonce `n` encoded as for
 `ENCRYPT()`, and the block count set to 1.  This is the same as calling
 `ENCRYPT()` on a plaintext consisting of 32 bytes of zeros and taking the first
 32 bytes. 

 * **`KDF(kdf_key, input)`**: `HMAC-SHA2-256(kdf_key, input)`.  

 * **`HASH(input)`**: `SHA2-256(input)` 

6.4. The AESGCM cipher parameters
---------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D with 128-bit tags.  The 96-bit nonce is formed
 by encoding 32 bits of zeros followed by big-endian encoding of `n`.
 
 * **`GETKEY(k, n)`**: Returns 32 bytes from concatenating two encryption calls
 to AES256 using key `k`.  The input is defined by encoding `n` into a 96-bit
 value as for `ENCRYPT()`, then setting this as the first 96 bits of two 128-bit
 blocks `B1` and `B2`.  The final 4 bytes of `B1` are set to (0, 0, 0, 2).  The
 final 4 bytes of `B2` are set to (0, 0, 0, 3).  `B1` and `B2` are both
 encrypted with AES256 and key `k`, and the resulting ciphertexts `C1` and `C2`
 are concatenated into the 32-byte output.  This is the same as calling
 `ENCRYPT()` on a plaintext consisting of 32 bytes of zeros and taking the first
 32 bytes.

 * **`KDF(kdf_key, input)`**: `HMAC-SHA2-256(kdf_key, input)`.  

 * **`HASH(input)`**: `SHA2-256(input)` 


7. Handshake and protocol names 
=========================

To produce a **concrete handshake name** for `HandshakeState.Initialize()` you
add the DH parameter and cipher parameter names to the handshake pattern name.
For example: `Noise_N_25519_ChaChaPoly`, `Noise_XXfallback_25519_AESGCM`, or
`Noise_IS_448_AESGCM`.

The concrete handshake name is identical to the **concrete protocol name**
unless the protocol uses pattern re-initialization. In that case, the protocol
should be given a special name (e.g.  "Pipe").  This name isn't used for
`HandshakeState.Initialize()` but fully defines the protocol for interop
purposes, e.g.  `Noise_Pipe_25519_AESGCM`.

8. Application responsibilities
================================

An application built on Noise must consider several issues:

 * **Extensibility**:  Applications are recommended to use an extensible data
 format for the payloads of all messages (e.g. JSON, Protocol Buffers) so that
 fields can be added in the future which are ignored by older implementations.

 * **Padding**:  Applications are recommended to use a data format for the
 payloads of all encrypted messages that allows the addition of padding data, so
 that payload lengths don't leak information.  Using an extensible data format,
 per the previous bullet, will typically suffice.

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
 one is included).  This allows extending the handshake with pattern
 re-initialization or other alternative messages in the future.


9. Security considerations
===========================

This section collects various security considerations:

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key `k`
 for encryption would be catastrophic.  Implementations must carefully follow
 the rules for incrementing nonces.   

 * **Fresh ephemerals**:  Every party in a Noise protocol should send a new
 ephemeral public key and perform a DH with it prior to sending any encrypted
 data.  Otherwise replay of a handshake message could trigger a catastrophic key
 reuse. This is one rationale behind the patterns in Section 4.

 * **Handshake names**:  The handshake name used with
 `HandshakeState.Initialize()` must uniquely identify a single handshake pattern
 for every key it's used with (whether ephemeral key pair, static key pair, or
 pre-shared key).  This is because the pattern specifies the role of all
 `cipherstate` calls within a handshake.  If the same secret key was used in
 different protocol executions with the same handshake name but a different
 sequence of `cipherstate` calls then bad interactions could occur between the
 executions.

10. Rationale
=============

This section collects various design rationale:

Noise messages are <= 65535 bytes because:

 * This allows safe streaming decryption, and random access decryption of large files.
 * This simplifies testing and reduces likelihood of memory or overflow errors in handling large messages
 * This restricts length fields to a standard size of 16 bits, aiding interop 
 * The overhead of larger standard length fields (e.g. 32 or 64 bits) might cost something for small messages, but the overhead of smaller length fields is insignificant for large messages.

Nonces are 64 bits in length because:

 * Some ciphers (e.g. Salsa20) only have 64 bit nonces
 * 64 bit nonces were used in the initial specification and implementations of ChaCha20, so Noise nonces can be used with these implementations.
 * 64 bits allows the entire nonce to be treated as an integer and incremented 
 * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if random nonces are acceptable.

The default cipher parameters use SHA2-256 because:

 * SHA2 is widely available
 * SHA2-256 requires less state than SHA2-512 and produces a sufficient-sized output (32 bytes)
 * SHA2-256 processes smaller input blocks than SHA2-512 (64 bytes vs 128 bytes), avoiding unnecessary calculation when processing smaller inputs

The cipher key must be 256 bits because:

 * The cipher key accumulates the DH output, so collision-resistance is desirable

Big-endian is preferred because:

 * Some ciphers use big-endian internally (e.g. GCM, SHA2).
 * While it's true that bignum libraries, Curve25519, Curve448, and
 ChaCha20/Poly1305 use little-endian, these will likely be handled by
 specialized libraries.
 * The Noise length fields, on the other hand, are more likely to be handled by
 network parsing code where big-endian "network byte order" is 
 traditional.


11. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

12. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Feedback on the spec came from: Moxie Marlinspike, Jason Donenfeld, Tiffany
Bennett, Jonathan Rudenberg, Stephen Touset, and Tony Arcieri.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


