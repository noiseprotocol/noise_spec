
Noise v1 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-08-31
 * **Revision:** 03 (work in progress)
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
DH-based key agreement to agree on a shared secret.  

The Noise framework can support any DH-based key agreement where each party has
a long-term key pair (aka **static key pair**) and/or **ephemeral key pair**.
The key agreement is described in terms of **descriptors** and **patterns**.  A
**descriptor** specifies the DH public keys and DH operations that comprise a
handshake message.  A **pattern** specifies the sequence of messages that
comprise a key agreement.  A pattern might describe a one-way encrypted message
or an interactive handshake.

For example, the following pattern (named `Noise_XX`) describes a mutually-authenticated
handshake:

    Noise_XX:  
      -> e
      <- e, dhee, s, dhse  
      -> s, dhse

The initiator's first message sends an ephemeral public key.  The responder's
first message sends an ephemeral public key, then sends the responder's static
public key ("s") encrypted under a symmetric key derived from DH between the
ephemerals ("dhee").  The initiator's final message contains the initiator's
static public key ("s") encrypted under a key derived from DH between the
ephemerals and DH between the initiator's ephemeral and responder's static key
pair.  The final shared key mixes a DH between the initiator's static and
responder's ephemeral with the previous two DHs to provide forward secrecy and
mutual authentication.

Each handshake message consists of a sequence of one or more DH public keys,
followed by a payload which may contain certificates, advertisements for
supported features, or anything else.  Some of the public keys and payloads may
be encrypted, as determined by the pattern.

After the handshake phase each party can send **transport messages**.  Each
transport message consists solely of an encrypted payload.

All Noise messages are 65535 bytes in length or less.  This allows safe
streaming decryption and 16-bit length fields.

An abstract handshake pattern can be instantiated by **DH parameters** and
**cipher parameters** to give a concrete protocol.

3.  `CipherState` and `HandshakeState` 
==================================

A Noise implementation can be viewed as three layers:

 * **DH parameters** and **cipher parameters** provide low-level crypto
 functions.

 * A **`CipherState`** object builds on the cipher parameters.  The
 `CipherState` mixes inputs into a secret key and uses that key for encryption
 and decryption.

 * A **`HandshakeState`** object builds on the `CipherState` and DH parameters.

The below sections describe each of these layers in turn.

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
 data `ad`.  If the authentication fails an error is signalled to the caller.

 * **`GETKEY(k, n)`**:  Calls the `ENCRYPT()` function with cipher key `k`,
 nonce `n`, and empty `ad` to encrypt a block of 256 zero bits.  Returns the
 first 256 bits from the encrypted output.  This function can usually be
 implemented more efficiently than by calling `ENCRYPT` (e.g.  by skipping the
 MAC calculation).

 * **`KDF(kdf_key, input)`**: Takes a `kdf_key` of 256 bits and some
 input data and returns a new value for the cipher key `k`.  The `kdf_key` will
 be a random secret key and the KDF should implement a "PRF" based on the
 `kdf_key`.  The KDF should also be a collision-resistant hash function given a
 known `kdf_key`.  `HMAC-SHA2-256` is an example KDF.

 * **`HASH(data)`**: Hashes some input data and returns a collision-resistant
 hash output of 256 bits. SHA2-256 is an example hash function.

3.2. The  `CipherState` object 
-------------------------------

A `CipherState` can mix inputs into its internal state, and can encrypt and
decrypt data based on its internal state.  A `CipherState` contains the
following variables:

 * **`k`**: A symmetric key of 256 bits for the cipher algorithm specified in
 the cipher parameters.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with `k`
 for encryption.

 * **`h`**: Either empty or 256 bits containing a hash output.  This is used as
 "associated data" for encryption.
 
A `CipherState` responds to the following methods:

 * **`Initialize()`**:  Sets `k` to all zeros, `n` to zero, and `h` to all zeros.
 
 * **`GetKey()`**: Calls `GETKEY(k, n)`, then increments `n` and returns the
 `GETKEY()` output.

 * **`MixKey(data)`**:  Sets `k` to `KDF(GetKey(), data)`.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  In other words,
 replaces `h` by the hash of `h` with `data` appended.

 * **`Split()`**:  Creates two new child `CipherState` objects by calling
 `GetKey()` to get the first child's `k`, then calling `GetKey()` to get the
 second child's `k`.  The children have `n` set to zero and `h` set to empty
 (i.e.  zero-length). The two children are returned.

 * **`Encrypt(plaintext)`**:  Calls `ENCRYPT(k, n, h, plaintext)` to get a
 ciphertext, then increments `n` and returns the ciphertext.

 * **`Decrypt(ciphertext)`**:  Calls `DECRYPT(k, n, h, ciphertext)` to get a
 plaintext, then increments `n` and returns the plaintext.  If an authentication
 failure occurs all variables are set to zeros and the error is signalled to the
 caller.

3.3.  Using the `HandshakeState` object 
---------------------------------------

To execute a Noise protocol you `Initialize()` a `HandshakeState` object, then
call `WriteHandshakeMessage()` and `ReadHandshakeMessage()` using successive
descriptors from a handshake pattern until the handshake is complete.  If a
decryption error occurs the handshake has failed and the `HandshakeState` is
deleted without sending further messages.

After the handshake is complete you call `EndHandshake()` which returns two
`CipherState` objects, the first for encrypting transport messages from
initiator to responder, and the second for messages in the other direction.
Then transport messages can be encrypted and decrypted by calling
`CipherState.Encrypt()` and `CipherState.Decrypt()`.

3.4. The `HandshakeState` object
---------------------------------

A `HandshakeState` contain the following variables:

 * **`cipherstate`**: `CipherState` object that provides symmetric crypto.

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

 * **`has_key`**: Boolean that records whether the `CipherState` has a secret
 key.

A `HandshakeState` responds to the following methods:

 * **`Initialize(new_cipherstate, name, preshared_key, static_keypair,
 preshared_ephemeral_keypair)`**: Takes a `CipherState` object.  Also takes a
 concrete handshake `name` (see Section 7) and `preshared_key` which are both
 variable-length byte sequences (the `preshared_key` may be empty).  Also takes
 optional static and "pre-shared ephemeral" keypairs.
 
   * Sets `cipherstate` to `new_cipherstate`.  Calls `cipherstate.Initialize()`.
   
   * Calls `cipherstate.MixKey(name || 0x00 || preshared_key)`.

   * If `preshared_key` isn't empty then sets `has_key` to `True`, otherwise
   sets it to `False`.
  
   * Sets `s` to `static_keypair` (which may be empty).

   * Sets `e` to `preshared_ephemeral_keypair` (which may be empty).

   * Sets `rs` and `re` to empty.


 * **`ConditionalEncryptAndMixHash(data)`**: If `has_key == True` sets `output_data =
 cipherstate.Encrypt(data)`, otherwise sets `output_data = data`.  Then calls
 `cipherstate.MixHash(data)` and returns `output_data`.

 * **`ConditionalDecryptAndMixHash(data, data_len)`**: If `has_key == True` sets
 `output_data` to `cipherstate.Decrypt()` on the next `data_len + 16` bytes of
 `data`, otherwise sets `output_data` to the next `data_len` bytes of `data`.
 Then calls `cipherstate.MixHash(output_data)` and returns `output_data`.

 * **`WriteHandshakeMessage(buffer, descriptor, payload)`**: Takes an empty byte
 buffer, a descriptor which is some sequence of the tokens from "e, s, dhee,
 dhes, dhse, dhss", and a `payload`.
 
    * Processes each token in the descriptor sequentially:
      * For "e":  Sets `e = GENERATE_KEYPAIR()` and appends the public key to the buffer.  
      * For "s":  If `s` is empty copies `e` to `s`.  Appends `ConditionalEncryptAndMixHash(s.public_key)` to the buffer.

      * For "dh*xy*" calls `cipherstate.MixKey(DH(x, ry))` and sets `has_key` to
      True.


    * Appends `ConditionalEncryptAndMixHash(payload)` to the buffer.

 * **`ReadHandshakeMessage(buffer, descriptor)`**: Takes a byte buffer
 containing a message, and a descriptor, and returns a payload.  If a decryption
 error occurs all variables are set to zeros and the error is signalled to the
 caller.

    * Processes each token in the descriptor sequentially:
      * For "e": Sets `re` to the next `DHLEN` bytes from `buffer`.  
      * For "s": Sets `rs` to `ConditionalDecryptAndMixHash(buffer, DHLEN)`.  
      
      * For "dh*xy*" calls `cipherstate.MixKey(DH(y, rx))` and sets `has_key` to
      True.

    * Sets `payload = ConditionalDecryptAndMixHash()` on the rest of the buffer and
    returns the payload.
   

 * **`EndHandshake()`**:  Returns two new `CipherState` objects by calling
 `cipherstate.Split()`.

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
equal to their ephemeral public key (a "dummy" static public key), this signals
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
      <- e, dhee, s, dhse              <- e, dhee, dhes, s, dhse                                
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


7. Handshake and Protocol names 
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


8. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be
catastrophic.  Implementations must carefully follow the rules for incrementing
nonces.   

To avoid catastrophic key reuse, every party in a Noise protocol should send a
fresh ephemeral public key and perform a DH with it prior to sending any
encrypted data.  This is one rationale behind the patterns in Section 4.

9. Rationale
=============

This section collects various design rationale:

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

 * While it's true that bignum libraries, Curve25519, Curve448, and
 ChaCha20/Poly1305 use little-endian, these will likely be handled by
 specialized libraries.
 * The Noise length fields, on the other hand, are more likely to be handled by
 network parsing code where big-endian "network byte order" is more
 traditional.


10. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

11. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Additional feedback on spec and pseudocode came from: Jason Donenfeld, Jonathan
Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


