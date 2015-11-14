
Noise v0 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-11-8
 * **Revision:** 18 (work in progress)
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
is described by **patterns**:  A **message pattern** specifies
the DH public keys that comprise a handshake message, and the DH operations
that are performed when sending or receiving that message.  A **handshake pattern** 
specifies the message patterns that comprise a handshake.

A handshake pattern can be instantiated by **DH functions**, **cipher
functions**, and a **hash function** to give a concrete protocol.  An
application using Noise must handle some **application responsibilities** on its
own, such as indicating message lengths.

3.  Message format
===================

All Noise messages are less than or equal to 65535 bytes in length, and can be
processed without parsing, since there are no type or length fields within the
message.  

A handshake message begins with a sequence of one or more DH public keys.
Following the public keys will be a **payload** which could be used to convey
certificates or other handshake data.  Encryption of static public keys and
payloads will occur after a DH operation establishes a shared secret key between
the two parties.  Ephemeral public keys aren't encrypted.  Zero-length payloads
are allowed.  If encrypted, a zero-length payload will result in a 16-byte
payload ciphertext, since encryption adds a 16-byte **authentication tag** to
each ciphertext.

A transport message consists solely of an encrypted payload. 

4.  Crypto algorithms
======================

A Noise protocol depends on **DH functions**, **cipher functions**, and a **hash
function**.

During a Noise handshake, the outputs from DH functions will be sequentially
mixed into a secret **chaining key (`ck`)**.  Cipher keys **(`k`)** derived from the
chaining key will be used to encrypt public keys and handshake payloads.  These
ciphertexts will also be sequentially mixed into a **hash variable (`h`)**.  The
`h` variable will be authenticated with every handshake ciphertext, to ensure
ciphertexts are bound to earlier data.

To represent a **cipher key** and its associated **nonce** we introduce the notion
of a **`CipherState`** which contains `k` and `n` variables.

To handle symmetric-key crypto during the handshake we introduce a
**`SymmetricState`** which extends a `CipherState` with `ck` and `h`
variables.  An implementation will create a `SymmetricState` to handle
a single Noise handshake, and can delete it once the handshake is finished.  

The below sections describe these concepts in more detail.


4.1. DH functions, cipher functions, and hash functions
--------------------------------------------------------

Noise depends on the following **DH functions** (and an associated constant):

 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
   sequence of bytes.  If the function detects an invalid public key, the
   output may be set to all zeros or any other value that doesn't leak
   information about the private key.

 * **`DHLEN`** = A constant specifying the size of public keys in bytes.

Noise depends on the following **cipher functions**:

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts `plaintext` using the cipher
   key `k` of 32 bytes and an 8-byte unsigned integer nonce `n` which must be
   unique for the key `k`.  Encryption must be done with an "AEAD" encryption
   mode with the associated data `ad` and must return a ciphertext that is the
   same size as the plaintext plus 16 bytes for an authentication tag.

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using a cipher
 key `k` of 32 bytes, an 8-byte unsigned integer nonce `n`, and associated
 data `ad`.  If the authentication fails an error is signaled to the caller.

Noise depends on the following **hash function** (and associated constants):

 * **`HASH(data)`**: Hashes some arbitrary-length data with a
   collision-resistant hash function and returns an output of `HASHLEN` bytes.

 * **`HASHLEN`** = A constant specifying the size in bytes of the hash output.
 Must be 32 or 64.

 * **`BLOCKLEN`** = A constant specifying the size in bytes that the hash
 function uses internally to divide its input for iterative processing.  This is
 needed to use the hash function within the HMAC construct (`BLOCKLEN` is `B` in
 RFC 2104).

Noise defines an additional function based on the above `HASH` function.  The
`||` operator indicates concatentation of byte sequences:

 * **`HKDF(chaining_key, input_key_material)`**:  Takes a `chaining_key` byte
   sequence of length `HASHLEN`, and an `input_key_material` byte sequence of
   arbitrary length.  Sets the value `temp_key = HMAC-HASH(chaining_key,
   input_key_material)`.  Sets the value `output1 = HMAC-HASH(temp_key, 0x01)`.
   Sets the value `output2 = HMAC-HASH(temp_key, output1 || 0x02)`.  These
   three values are all `HASHLEN` bytes in length.  Returns the pair
   (`output1`, `output2`).


4.2. The  `CipherState` object 
-------------------------------

A `CipherState` can encrypt and decrypt data based on its `k` and `n` variables:

 * **`k`**: A cipher key of 32 bytes.

 * **`n`**: An 8-byte unsigned integer nonce.

A `CipherState` responds to the following methods.  The `++` post-increment
operator applied to `n` means "use the current `n` value, then increment it".

 * **`EncryptAndIncrement(ad, plaintext)`**:  Returns `ENCRYPT(k, n++, ad,
 plaintext)`.

 * **`DecryptAndIncrement(ad, ciphertext)`**:  Returns `DECRYPT(k, n++, ad,
 ciphertext)`.  If an authentication failure occurs the error is signaled to the
 caller.

4.3. The `SymmetricState` object
-----------------------------------------

A `SymmetricState` object extends a `CipherState` with the following
variables:

 * **`has_key`**: A boolean that records whether key `k` is a secret value.
 
 * **`ck`**: A chaining key of `HASHLEN` bytes.
 
 * **`h`**: A hash output of `HASHLEN` bytes.

A `SymmetricState` responds to the following methods:   
 
 * **`InitializeSymmetric(handshake_name)`**:  Takes an arbitrary-length
 `handshake_name`.  Leaves `k` and `n` uninitialized, and sets `has_key =
 False`.  If `handshake_name` is less than or equal to `HASHLEN` bytes in
 length, sets `h` equal to `handshake_name` with zero bytes appended to make
 `HASHLEN` bytes.  Otherwise sets `h = HASH(handshake_name)`.  Sets `ck = h`.

 * **`MixKey(input_key_material)`**:  Sets `ck, k = HKDF(ck,
   input_key_material)`.  If `HASHLEN` is not 32, then the second output from
   `HKDF()` is truncated to 32 bytes to match `k`.  Sets `n = 0` and `has_key =
   True`.
  
 * **`MixHash(data)`**:  Sets `h = HASH(h || data)`.

 * **`EncryptAndHash(plaintext)`**: If `has_key == True` sets `ciphertext =
 EncryptAndIncrement(h, plaintext)`, calls `MixHash(ciphertext)`, and returns
 `ciphertext`.  Otherwise calls `MixHash(plaintext)` and returns `plaintext`.

 * **`DecryptAndHash(data)`**: If `has_key == True` sets `plaintext =
 DecryptAndIncrement(h, data)`, calls `MixHash(data)`, and returns `plaintext`.
 Otherwise calls `MixHash(data)` and returns `data`.

 * **`Split()`**:  Creates two child `CipherState` objects by calling `HKDF(ck,
   empty)` where `empty` is a zero-length byte sequence.  The first child's `k`
   is set to the first output from `HKDF()`, and the second child's `k` is set
   to the second output from `HKDF()`.  If `HASHLEN` is not 32, then each
   output from `HKDF()` is truncated to 32 bytes to match `k`.  Both children's
   `n` value is set to zero.  Both children are returned.  The caller will use
   the child `CipherState` objects to encrypt transport messages, as described
   in the next section.


5.  The handshake algorithm
============================

A pattern for a handshake message is some sequence of **tokens** from the set
("e", "s", "dhee", "dhes", "dhse", "dhss").  To send (or receive) a handshake
message you iterate through the tokens that comprise the message's pattern.
For each token you write (or read) the public key it specifies, or perform the
DH operation it specifies.  

To provide a rigorous description we introduce the notion of a `HandshakeState`
object.  A `HandshakeState` extends a `SymmetricState` with DH variables.  

To execute a Noise protocol you `Initialize()` a `HandshakeState`.  During
initialization you specify any local key pairs, and any public keys for the
remote party you have knowledge of.  You may optionally specify **prologue**
data that both parties will confirm is identical (such as previously exchanged
version negotiation messages), and/or a **pre-shared key** that will be used to
encrypt and authenticate.  

After `Initialize()` you call `WriteMessage()` and `ReadMessage()` to process
each handshake message.  If a decryption error occurs the handshake has failed
and the `HandshakeState` is deleted without sending further messages.

Processing the final handshake message returns two `CipherState` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  At that point the `HandshakeState`
may be deleted.  Transport messages are then encrypted and decrypted by calling
`EncryptAndIncrement()` and `DecryptAndIncrement()` on the relevant
`CipherState` with zero-length associated data.


5.1. The `HandshakeState` object
---------------------------------

A `HandshakeState` object extends a `SymmetricState` with the following
variables, any of which may be empty:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

A `HandshakeState` also has the following variables:

 * **`message_patterns`**: A sequence of message patterns.  Each message pattern is a
   sequence of tokens from the set ("s", "e", "dhee", "dhes", "dhse", "dhss).

 * **`message_index`**: An integer indicating the next pattern to fetch from
 `message_patterns`.

 * **`psk`**:  A boolean specifying whether a `preshared_key` is in use.

A `HandshakeState` responds to the following methods:

 * **`Initialize(handshake_pattern, initiator, prologue, preshared_key, new_s,
 new_e, new_rs, new_re)`**: Takes a valid handshake pattern (see Section 6), and
 an `initiator` boolean specifying this party's role.  Takes a `prologue` byte
 sequence which may be zero-length, or which may contain context information
 that both parties want to confirm is identical, such as protocol or version
 negotiation messages sent previously.  Takes a `preshared_key` which may be
 empty, or a byte sequence containing secret data known only to the initiator
 and responder.  Takes a set of DH keypairs and public keys for initializing
 local variables, any of which may be empty.
 
   * Derives a `handshake_name` byte sequence by combining the names for the 
   handshake pattern and crypto functions, as specified in Section 9. Calls 
   `InitializeSymmetric(handshake_name)`.

   * Calls `MixHash(prologue)`.

   * If `preshared_key` is non-empty, calls `MixKey(preshared_key)`, then
     `MixHash(k)`, and sets `psk = True`.  Otherwise sets `psk = False`.

   * Sets `s`, `e`, `rs`, and `re` to the corresponding arguments.
   
   * Calls `MixHash()` once for each public key listed in the pre-messages from
   `handshake_pattern`, passing in that public key as input (see Section 6).  If
   both initiator and responder have pre-messages, the initiator's public keys
   are hashed first.

   * Sets `message_patterns` to the message patterns from `handshake_pattern`.

   * Sets `message_index = 0` (i.e. the first message pattern).

 * **`WriteMessage(payload, message_buffer)`**: Takes a `payload` byte sequence
   which may be zero-length, and a `message_buffer` to write the output into.

    * Fetches the next message pattern from `message_patterns[message_index]`,
    increments `message_index`, and sequentially processes each token from the
    message pattern:

      * For "e":  Sets `e = GENERATE_KEYPAIR()`, overwriting any previous value
      for `e`.  Appends `e.public_key` to the buffer.  Calls
      `MixHash(e.public_key)`.  If `psk` is true, calls `MixKey(e.public_key)`.

      * For "s":  Appends `EncryptAndHash(s.public_key)` to the buffer.  
      
      * For "dh*xy*":  Calls `MixKey(DH(x, ry))`.

    * Appends `EncryptAndHash(payload)` to the buffer.  
    
    * If there are no more message patterns returns two new `CipherState`
      objects by calling `Split()`.

 * **`ReadMessage(message, payload_buffer)`**: Takes a byte sequence containing
   a Noise handshake message, and a `payload_buffer` to write the message's
   plaintext payload into.

    * Fetches the message pattern from `message_patterns[message_index]`,
    increments `message_index`, and sequentially processes each token from the
    message pattern:

      * For "e": Sets `re` to the next `DHLEN` bytes from the buffer. Calls
      `MixHash(e.public_key)`.  If `psk` is true, calls `MixKey(e.public_key)`.
      
      * For "s": Sets `data` to the next `DHLEN + 16` bytes of the message if
      `has_key == True`, or to the next `DHLEN` bytes otherwise.  Sets `rs` to
      `DecryptAndHash(data)`.  
      
      * For "dh*xy*":  Calls `MixKey(DH(y, rx))`.  

    * Copies the output from `DecryptAndHash(remaining_message)` into the `payload_buffer`.
  
    * If there are no more message patterns returns two new `CipherState`
      objects by calling `Split()`.
    
6. Handshake patterns 
======================

A message pattern is some sequence of tokens from the set ("e", "s", "dhee", "dhes", "dhse",
"dhss").  A handshake pattern consists of:

 * A pattern for the initiator's "pre-message" that is either "s", "e",
   "s, e", or empty.

 * A pattern for the responder's "pre-message" that is either "s", "e",
   "s, e", or empty.

 * A sequence of message patterns for the actual handshake messages

The pre-messages represent an exchange of public keys that was somehow
performed prior to the handshake, so these public keys should be inputs to
`Initialize()`.  

The first actual handshake message in the sequence is sent from the initiator
to the responder; the next is sent by the responder, and so on. All messsages
described by the handshake pattern must be sent in order.  

The following handshake pattern describes an unauthenticated DH handshake:

    Noise_NN():
      -> e
      <- e, dhee

The handshake pattern name is `Noise_NN`.  The empty parentheses indicate that neither
party is initialized with any key pairs.  The tokens "e" and/or "s" in
parentheses would indicate that the initiator is initialized with the corresponding
key pairs.  The tokens "re" and/or "rs" would indicate the same thing for the
responder.

Pre-messages are shown as patterns prior to the delimiter "\-\-\-\-\-\-".
During `Initialize()`, `MixHash()` is called on any pre-message public keys in
the order they are listed.

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral:

    Noise_NK(rs):
      <- s
      ------
      -> e, dhes 
      <- e, dhee

6.1 Pattern validity 
----------------------

Noise patterns must be **valid** in two senses:

 * Parties can only send static public keys they possess, or perform DH between
 keys they possess.

 * Because Noise uses ephemeral public keys as nonces, parties must send an
 ephemeral public key as the first token of the first message they send.  Also,
 after sending an ephemeral public key, parties must never send encrypted data
 unless they have performed DH between their current ephemeral and all of the
 other party's key pairs.  

Patterns failing the first check will obviously abort the program.  Patterns
failing the second check could result in subtle but catastrophic security flaws.

6.2. One-way patterns 
----------------------

The following patterns represent "one-way" handshakes supporting a one-way
stream of data from a sender to a recipient.  

Following these one-way handshakes the sender can send a stream of transport
messages, encrypting them using the first `CipherState` returned by `Split()`.
The second `CipherState` from `Split()` is discarded - the recipient must not
send any messages using it.


     N  = no static key for sender
     K  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    Noise_N(rs):
      <- s
      ------
      -> e, dhes

    Noise_K(s, rs):
      -> s
      <- s
      ------
      -> e, dhes, dhss

    Noise_X(s, rs):
      <- s
      ------
      -> e, dhes, s, dhss

6.3. Interactive patterns 
--------------------------

The following 16 patterns represent protocols where the initiator and responder
exchange messages to agree on a shared key.

     N_ = no static key for initiator
     K_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder
     I_ = static key for initiator immediately transmitted to responder
 
     _N = no static key for responder
     _K = static key for responder known to initiator
     _E = static key plus a semi-ephemeral key for responder known to initiator
     _X = static key for responder transmitted to initiator


    Noise_NN():                      Noise_KN(s):              
      -> e                             -> s                       
      <- e, dhee                       ------                     
                                       -> e                       
                                       <- e, dhee, dhes           
                                             
    Noise_NK(rs):                    Noise_KK(s, rs):
      <- s                             -> s                       
      ------                           <- s                       
      -> e, dhes                       ------                     
      <- e, dhee                       -> e, dhes, dhss           
                                       <- e, dhee, dhes           
                                              
    Noise_NE(rs, re):                Noise_KE(s, rs, re):      
      <- s, e                          -> s
      ------                           <- s, e
      -> e, dhee, dhes                 ------                     
      <- e, dhee                       -> e, dhee, dhes, dhse     
                                       <- e, dhee, dhes           
                                                                     
    Noise_NX(rs):                    Noise_KX(s, rs):          
      -> e                             -> s                       
      <- e, dhee, s, dhse              ------                     
                                       -> e                       
                                       <- e, dhee, dhes, s, dhse  
                            

    Noise_XN(s):                     Noise_IN(s):
      -> e                             -> e, s
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    Noise_XK(s, rs):                 Noise_IK(s, rs):            
      <- s                             <- s                         
      ------                           ------                       
      -> e, dhes                       -> e, dhes, s, dhss          
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    Noise_XE(s, rs, re):             Noise_IE(s, rs, re):
      <- s, e                          <- s, e                      
      ------                           ------                       
      -> e, dhee, dhes                 -> e, dhee, dhes, s, dhse    
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                       
    Noise_XX(s, rs):                 Noise_IX(s, rs):
      -> e                             -> e, s
      <- e, dhee, s, dhse              <- e, dhee, dhes, s, dhse                                
      -> s, dhse

7. Handshake re-initialization and "Noise Pipes"
===============================================

A protocol may support **handshake re-initialization**.  In this case, the
recipient of a handshake message must also receive some indication whether this
is the next message in the current handshake, or whether to re-initialize the
`HandshakeState` and perform a different handshake (see discussion on "Type
fields" in Section 10).

By way of example, this section defines the **Noise Pipe** protocol.  This
protocol uses two patterns defined in the previous section: `Noise_XX` is used
for a full handshake.  `Noise_IK` is used for an abbreviated handshake that
allows the initiator to send some encrypted data in the first message.  The
abbreviated handshake can be used if the initiator has pre-knowledge of the
responder's static public key; for example, the initiator might cache the
responder's static public key after a full handshake, and attempt the
abbreviated handshake in the future.

If the responder fails to decrypt the first `Noise_IK` message (perhaps due to
changing her static key), the responder will initiate a new `Noise_XXfallback`
handshake identical to `Noise_XX` except re-using the ephemeral public key from
the first `Noise_IK` message as a pre-message public key.

Below are the three patterns used for Noise Pipes:

    Noise_XX(s, rs):  
      -> e
      <- e, dhee, s, dhse  
      -> s, dhse

    Noise_IK(s, rs):                   
      <- s                         
      ------
      -> e, dhes, s, dhss          
      <- e, dhee, dhes             
                                        
    Noise_XXfallback(s, rs, re):                   
      <- e
      ------
      -> e, dhee, s, dhse
      <- s, dhse

Note that in the fallback case, the initiator and responder roles are switched:
If Alice inititates a `Noise_IK` handshake with Bob, Bob might 
initiate a `Noise_XX_fallback` handshake.

Note also that encrypted data sent in the first `Noise_IK` message is
susceptible to replay attacks.  Also, if the responder's static private key is
compromised, `Noise_IK` initial messages can be decrypted and/or forged.

To distinguish these patterns, each handshake message will be preceded by a
`type` byte:

 * If `type == 0` in the initiator's first message then the initiator is performing
 a `Noise_XX` handshake.

 * If `type == 1` in the initiator's first message then the initiator
 is performing a `Noise_IK` handshake.

 * If `type == 1` in the responder's first `Noise_IK` response then the
 responder failed to authenticate the initiator's `Noise_IK` message and is
 performing a `Noise_XXfallback` handshake, using the initiator's ephemeral
 public key as a pre-message.

 * In all other cases, `type` will be 0.

So that Noise pipes can be used with arbitrary lower-level protocols, handshake
messages are sent with the `type` byte followed by a 2-byte big-endian length
field denoting the length of the following Noise message, followed by a Noise
handshake message.  Transport messages are sent with only the 2-byte length
field, followed by the Noise tranport message.

8. DH functions, cipher functions, and hash functions
======================================================

8.1. The 25519 DH functions
----------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 DH function (aka "X25519"
   in some other specifications).  If the function detects an invalid public
   key, the output may be set to all zeros or any other value that doesn't leak
   information about the private key.

 * **`DHLEN`** = 32

8.2. The 448 DH functions
--------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve448 DH function (aka "X448" in
   some other specifications).  If the function detects an invalid public key,
   the output may be set to all zeros or any other value that doesn't leak
   information about the private key.

 * **`DHLEN`** = 56

8.3. The ChaChaPoly cipher functions
------------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is formed by encoding
 32 bits of zeros followed by little-endian encoding of `n`.  (Earlier
 implementations of ChaCha20 used a 64-bit nonce, in which case it's compatible
 to encode `n` directly into the ChaCha20 nonce).

8.4. The AESGCM cipher functions
---------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D with 128-bit tags.  The 96-bit nonce is formed
 by encoding 32 bits of zeros followed by big-endian encoding of `n`.

8.5. The SHA256 hash function
------------------------------

 * **`HASH(input)`**: `SHA2-256(input)` 

 * **`HASHLEN`** = 32

 * **`BLOCKLEN`** = 64

8.5. The SHA512 hash function
------------------------------

 * **`HASH(input)`**: `SHA2-512(input)` 
 
 * **`HASHLEN`** = 64

 * **`BLOCKLEN`** = 128

8.6. The BLAKE2s hash function
-------------------------------

 * **`HASH(input)`**: `BLAKE2s(input)` with digest length 32.

 * **`HASHLEN`** = 32

 * **`BLOCKLEN`** = 64

8.6. The BLAKE2b hash function
-------------------------------

 * **`HASH(input)`**: `BLAKE2b(input)` with digest length 64.

 * **`HASHLEN`** = 64

 * **`BLOCKLEN`** = 128

9. Handshake names 
=========================

To produce a **handshake name** for `Initialize()` you concatenate the names
for the handshake pattern, the DH functions, the cipher functions, and the hash
function.  For example: 

 * `Noise_XX_25519_AESGCM_SHA256`

 * `Noise_N_25519_ChaChaPoly_BLAKE2s`

 * `Noise_XXfallback_448_AESGCM_SHA512`

 * `Noise_IK_448_ChaChaPoly_BLAKE2b`

If a pre-shared key is in use, then `NoisePSK` is used instead of `Noise`:

 * `NoisePSK_XX_25519_AESGCM_SHA256`

 * `NoisePSK_N_25519_ChaChaPoly_BLAKE2s` 
 
 * `NoisePSK_XXfallback_448_AESGCM_SHA512`

 * `NoisePSK_IK_448_ChaChaPoly_BLAKE2b`


10. Application responsibilities
================================

An application built on Noise must consider several issues:

 * **Choosing crypto functions**:  The `25519` DH functions are recommended for
 most uses, along with either `AESGCM_SHA256` or `ChaChaPoly_BLAKE2s`.  For an
 extreme security margin, you could use the `448` DH functions with either
 `AESGCM_SHA512` or `ChaChaPoly_BLAKE2b`.

 * **Extensibility**:  Applications are recommended to use an extensible data
   format for the payloads of all messages (e.g. JSON, Protocol Buffers).  This
   ensures that fields can be added in the future which are ignored by older
   implementations.

 * **Padding**:  Applications are recommended to use a data format for the
   payloads of all encrypted messages that allows padding.  This allows
   implementations to avoid leaking information about message sizes.  Using an
   extensible data format, per the previous bullet, will typically suffice.

 * **Termination**: Applications must consider that a sequence of Noise
 transport messages could be truncated by an attacker.  Applications should
 include explicit length fields or termination signals inside of transport
 payloads to signal the end of a stream of transport messages. 

 * **Length fields**:  Applications must handle any framing or additional length
 fields for Noise messages, considering that a Noise message may be up to 65535
 bytes in length.  If an explicit length field is needed, applications are
 recommended to add a 16-bit big-endian length field prior to each message.

 * **Type fields**:  Applications are recommended to include a single-byte type
   field prior to each Noise handshake message (and prior to the length field,
   if one is included).  Applications would reject messages with unknown type.
   This allows extending the handshake with handshake re-initialization or
   other alternative messages in the future.

11. Security considerations
===========================

This section collects various security considerations:

 * **Termination**:  Preventing attackers from truncating a stream of transport
   messages is an application responsibility.  See above.

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key `k`
 for encryption would be catastrophic.  Implementations must carefully follow
 the rules for nonces.   

 * **Fresh ephemerals**:  Every party in a Noise protocol should send a new
   ephemeral public key and perform a DH with it prior to sending any encrypted
   data.  Otherwise replay of a handshake message could trigger catastrophic
   key reuse. This is one rationale behind the patterns in Section 6.  It's
   also the reason why one-way handshakes only allow transport messages from
   the sender, not the recipient.

 * **Handshake names**:  The handshake name used with `Initialize()` must
 uniquely identify the combination of handshake pattern and crypto functions for
 every key it's used with (whether ephemeral key pair or static key pair).  If
 the same secret key was reused with the same handshake name but a different set
 of cryptographic operations then bad interactions could occur.

 * **Pre-shared keys**:  Pre-shared keys should be secret values with 256 bits
 of entropy (or more).

 * **Channel binding**:  Depending on the DH functions, it might be possible
   for a malicious party to engage in multiple sessions that derive the same
   shared secret key (e.g. if setting her public keys to invalid values causes
   DH outputs of zero).  If a higher-level protocol wants a unique "channel
   binding" value for referring to a Noise session it should use the value of
   `h` after the final handshake message, not `ck`.

 * **Implementation fingerprinting**:  If this protocol is used in settings with
   anonymous parties, care should be taken that implementations behave
   identically in all cases.  This may require mandating exact behavior for
   handling of invalid DH public keys.

12. Rationale
=============

This section collects various design rationale:

Noise messages are <= 65535 bytes because:

 * This allows safe streaming decryption, and random access decryption of large files.
 * This simplifies testing and reduces likelihood of memory or overflow errors in handling large messages.
 * This restricts length fields to a standard size of 16 bits, aiding interop.
 * The overhead of larger standard length fields (e.g. 32 or 64 bits) might
   cost something for small messages, but the overhead of smaller length fields
   is insignificant for large messages.
 * This discourage mis-use of handshake payloads for large data transfers.

Nonces are 64 bits in length because:

 * Some ciphers (e.g. Salsa20) only have 64 bit nonces.
 * 64 bit nonces were used in the initial specification and implementations of
   ChaCha20, so Noise nonces can be used with these implementations.
 * 64 bits makes it easy for the entire nonce to be treated as an integer and incremented.
 * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if
   random nonces are acceptable.

The recommended hash function families are SHA2 and BLAKE2 because:

 * SHA2 is widely available.
 * SHA2 is often used alongside AES.
 * BLAKE2 is similar to ChaCha20.

Hash output lengths of 256 bits are supported because:

 * SHA2-256 and BLAKE2s have sufficient collision-resistance at the 128-bit security level.
 * SHA2-256 and BLAKE2s require less RAM, and less calculation when processing
 smaller inputs (due to smaller block size), then their larger brethren
 (SHA2-512 and BLAKE2b).
 * SHA2-256 and BLAKE2s are faster on 32-bit processors than their larger brethren.

Cipher keys are 256 bits because:

 * 256 bits is a conservative length for cipher keys when considering cryptanalytic
   safety margins, time/memory tradeoffs, multi-key attacks, and quantum attacks.

The authentication tag is 128 bits because:

 * Some algorithms (e.g. GCM) lose more security than an ideal MAC when truncated.
 * Noise may be used in a wide variety of contexts, including where attackers
   can receive rapid feedback on whether MAC guesses are correct.
 * A single fixed length is simpler than supporting variable-length tags.

Big-endian is preferred because:

 * While it's true that bignum libraries, Curve25519, Curve448, and
 ChaCha20/Poly1305 use little-endian, these will likely be handled by
 specialized libraries.
 * Some ciphers use big-endian internally (e.g. GCM, SHA2).
 * The Noise length fields are likely to be handled by
 parsing code where big-endian "network byte order" is 
 traditional.

The `MixKey()` design uses `HKDF` because:

 * HKDF is a conservative and widely used design.

`MixHash()` is used instead of `MixKey()` because:

 * `MixHash()` is more efficient than `MixKey()`.
 * `MixHash()` avoids any IPR concerns regarding mixing identity data into
   session keys (see KEA+).
 * `MixHash()` produces a non-secret `h` value that might be useful to
   higher-level protocols, e.g. for channel-binding.



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

Thanks to Karthikeyan Bhargavan for some editorial feedback.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.
