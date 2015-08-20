
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

**Messages** are exchanged between parties.  Each message will contain zero or
more DH public keys followed by a payload.  Either the public keys or payload
may be encrypted.

A **protocol** consists of some sequence of messages between a pair of
parties.

Each party will have a **session** which contains the state used to
process messages.

2.2. The handshake: descriptors and patterns
-------------------------------------------

A Noise protocol begins with a handshake phase where both parties can send
**handshake messages** containing DH public keys and perform DH operations to
agree on a shared secret.  The handshake payloads can contain data relevant to
handshaking, like certificates, or advertisements of new version support.

A **descriptor** specifies the DH keys and DH operations that comprise a
handshake message.

A **pattern** specifies the sequence of descriptors that comprise a handshake.

A simple pattern might describe a one-shot encrypted message from Alice to Bob.
A more complex pattern might describe an interactive handshake.

2.3.  After the handshake: application messages
------------------------------------------------

After the handshake messages each party will share a secret key and can
send **application messages** which typically consist of encrypted payloads
without DH public keys.

Several operations can be used to control the encryption, including splitting
the shared key into separate keys for duplex communications, explicit nonces for
out-of-order messages, and "stepping" the key for forward-secrecy.

2.4. Key agreement
-------------------

Noise can implement handshakes where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that exist only during
the protocol.

2.5. Ciphersuites
------------------

A Noise protocol can be described abstractly in terms of its handshake pattern
and handling of application messages.

A **ciphersuite** instantiates the crypto functions to give a concrete protocol.
Different ciphersuites could use different elliptic curves for the DH function,
or different symmetric-key primitives.

2.6. Conventions
-----------------

Noise comes with conventions for things like type and length fields, padding,
error handling, etc.  These aren't a mandatory part of Noise, but adoption is
encouraged.

3. Sessions
============

A Noise session can be viewed as three layers:

 * A ciphersuite provides low-level crypto functions.

 * A kernel object builds on the symmetric-key ciphersuite functions.  The
 kernel provides methods for mixing inputs into a secret key and using that key
 for encryption and decryption.

 * A session object builds on the kernel and provides methods for handling
 public keys and payloads.

The below sections describe each of these layers in turn.

3.1. Ciphersuite functions
---------------------------

Noise depends on the following constants and functions, which are supplied by a
**ciphersuite**:

 * **`klen`**: A constant specifying the length in bytes of symmetric keys used
 for encryption.  These keys are used to accumulate the results of DH
 operations, so `klen` must be >= 32 to provide collision resistance.  32 is
 recommended.

 * **`hlen`**: A constant specifying the length in bytes of hash outputs.  Must
 be >= 32 to provide collision resistance.  32 is recommended.

 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts `plaintext` using the cipher key `k` of
 `klen` bytes, and a 64-bit unsigned integer nonce `n` which must be unique for
 the key `k`.  Encryption must be done with an "AEAD" encryption mode with the
 associated data `ad`.  This must be a deterministic function (i.e.  it shall
 not add a random IV; this ensures the `GETKEY()` function is deterministic).

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using the cipher
 key `k` of `klen` bytes, a 64-bit unsigned integer nonce `n`, and associated
 data `ad`.

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

3.2.  Kernel state and methods
-------------------------------

To simplify the descriptions and improve modularity, a session contains a
**kernel**.  The kernel can mix inputs into its internal state, and can encrypt
and decrypt data based on its internal state.  

A kernel object contains the following state variables:

 * **`k`**: A symmetric key of `klen` bytes for the cipher algorithm specified
 in the ciphersuite.  This mixes together the results of all DH operations, and
 is used for encryption.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with `k`
 for encryption.

 * **`h`**: Either empty or `hlen` bytes containtaining a hash output.  This
 value mixes together relevant handshake data, and is then authenticated by
 encryption.
 
A kernel responds to the following methods:

 * **`InitializeKernel()`**:  Sets `k` to all zero bytes, `n` to zero, and `h`
 to empty.

 * **`SetNonce(nonce)`**:  Sets `n` to `nonce`.

 * **`StepKey()`**:  Sets `k` to `GETKEY(k, n)`.  Sets `n` to zero.

 * **`MixKey(type, data)`**:  Sets `k` to `KDF(GETKEY(k, n), type || data)`.  In
 other words, prepends `type` to `data` before sending it through the KDF.  Then
 sets `n` to zero.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  In other words,
 replaces `h` by the hash of `h` with `data` appended.

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

3.3.  Session state and methods
--------------------------------

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

 * **`DHSS()`**: Calls `MixKey(0, DH(s, rs))` on the kernel.

 * **`DHEE()`**: Calls `MixKey(0, DH(e, re))` on the kernel.

 * **`DHSE()`**: Calls `MixKey(0, DH(s, re))` on the kernel.

 * **`DHES()`**: Calls `MixKey(0, DH(e, rs))` on the kernel.

4. Handshake messages
======================

4.1. Descriptors
-----------------
A descriptor is a comma-separated list containing some of the following tokens.
The tokens describe the sequential actions taken by the writer or reader of a
message.

 * **`s`**: Calls the session's `WriteStatic()` or `ReadStatic()` method. 

 * **`e`**: Calls the session's `WriteEphemeral()` or `ReadEphemeral()` method.

 * **`dhss, dhee, dhse, dhes`**: Given `dhxy` calls `DHXY()` for the
 writer and `DHYX()` for the reader.

A pattern is a sequence of descriptors. Descriptors with right-pointing arrows
are for messages created and sent by the protocol initiator; with left-pointing
arrows are for messages sent by the responder.  All messsages described by the
pattern must be sent in order.  The following pattern describes an
unauthenticated DH handshake:

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

4.1. Message processing
------------------------

Writing a handshake message requires:

 * A session
 
 * A buffer to write the message into

 * A descriptor 

 * Payload data (may be zero bytes).

First the descriptor is processed sequentially.  Then `WritePayload(buffer,
payload)` is called on the session.

To read the message the descriptor is processed sequentially.  Then
`ReadPayload(buffer)` is called to return the payload.

4.2. Handshake processing
--------------------------

Every Noise protocol begins by executing a handshake pattern.  This requires:

 * A session

 * Protocol name (may be zero bytes)

 * (Optional) Pre-knowledge of the remote party's static and/or ephemeral public keys

 * (Optional) A static key pair

 * (Optional) Pre-shared symmetric key

 * A pattern of descriptors

First `InitializeSession()` is called.  

If no pre-shared key is present, `MixKey(0, name)` is called.  If a pre-shared
key is present, `MixKey(1, name)` is called, followed by `MixKey(0,
preshared_key)`.

If the party has a static key pair, then `SetStaticKeyPair(static)` is called.

Next any pre-messages in the pattern are processed.  This has no effect except
performing more `MixHash()` calls based on the party's pre-knowledge.

Following this the parties read and write handshake messages.  After every
handshake message `MixHash(payload)` is called, except for the last handshake
message.  After the last handshake message `ClearHash()` is called.

4.3. Branching
---------------

Branching allows parties to alter the protocol that is being executed on the
fly.  For example: 

 * A client could choose whether to authenticate itself based on the server's
 response.

 * A server could choose which ciphersuite to support based on options offered
 by the client.

 * A client could attempt an abbreviated handshake based on cached information,
 and if this information is stale the server can fall back to a full handshake.

Branching requires:

 * Designating a particular message as a branch point.

 * Assigning branch numbers to the alternatives (where branch number zero is the
 default, and other branches count up from there).

 * For each alternative, specifying whether it uses previous session state,
 or re-initializes the session.

 * Having a way for messages to indicate which branch is taken (see the
 "Conventions" section for a recommendation).


If a non-zero branch is taken and session state is re-used, `MixKey()` is
called, with the branch number as the type, and empty data.

If a non-zero branch is taken and session state is to be re-initialized, then
the message is treated as starting a new handshake, and the steps from 4.2 are
performed, except `InitializeKernel()` is called in place of
`InitializeSession()` to allow previously exchanged public keys to be re-used.


5. Handshake patterns
======================

The following patterns represent the mainstream use of Noise.  Other patterns
can be defined in other documents.

5.1. Box patterns
------------------

The following "Box" patterns represent one-shot messages from a sender to a
recipient.  BoxX is recommended for most uses.

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

5.2. Interactive patterns
--------------------------

The following 16 "Handshake" patterns represent protocols where the initiator
and responder exchange messages to agree on a shared key.  HandshakeXX is
recommended for most uses.

     N_ = no static key for initiator
     K_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder
     I_ = static key for inititiator immediately transmitted to responder
 
     _N = no static key for responder
     _K = static key for responder known to initiator
     _E = static key plus a semi-ephemeral key for responder known to initiator
     _X = static key for responder transmitted to initiator


    HandshakeNN:                      HandshakeKN:                 
      -> e                              -> s                       
      <- e, dhee                        ------                     
                                        -> e                       
                                        <- e, dhee, dhes           
                                             
    HandshakeNK:                      HandshakeKK:                 
      <- s                              <- s                       
      ------                            -> s                       
      -> e, dhes                        ------                     
      <- e, dhee                        -> e, dhes, dhss           
                                        <- e, dhee, dhes           
                                              
    HandshakeNE:                      HandshakeKE:                 
      <- s, e                           <- s, e                    
      ------                            -> s                       
      -> e, dhee, dhes                  ------                     
      <- e, dhee                        -> e, dhee, dhes, dhse     
                                        <- e, dhee, dhes           
                                                                     
    HandshakeNX:                      HandshakeKX:                 
      -> e                              -> s                       
      <- e, dhee, s, dhse               ------                     
                                        -> e                       
                                        <- e, dhee, dhes, s, dhse  
                            

    HandshakeXN:                      HandshakeIN:                   
      -> e                              -> e, s                      
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    HandshakeXK:                      HandshakeIK:                   
      <- s                              <- s                         
      ------                            ------                       
      -> e, dhes                        -> e, dhes, s, dhss          
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    HandshakeXE:                      HandshakeIE:                   
      <- s, e                           <- s, e                      
      ------                            ------                       
      -> e, dhee, dhes                  -> e, dhee, dhes, s, dhse    
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                       
    HandshakeXX:                      HandshakeIX:                  
      -> e                              -> e, s                     
      <- e, dhee, s, dhse               <- e, dhee, dhes, s, dhse                                
      -> s, dhse

6. Application messages
========================

After the last handshake message, the parties can send application messages in several ways:

 * **One-way stream**: One party can send a stream of messages.

 * **Alternating stream**: Both parties can alternate sending messages, using a
 single session.

 * **Two streams**: Both parties can send a stream of messages, using
 separate sessions.  In this case, `Split()` is called with the initiator using
 the original session and the responder using the new session.

A stream of messages may be **fixed-length** or **variable-length**, depending on
whether it's known in advance how many messages will be sent.

Out of order messages can be handled by prepending `n` as an **explicit nonce**
to each message.  The recipient will call `SetNonce()` on the explicit nonce.

Key updating techniques can be used within a stream:

 * **Stepping**: After sending a message, `StepKey()` is called to destroy
 the old key and replace it with a new one.  This provides security for old
 messages against future compromises.

 * **Splitting**: Each message is encrypted by calling `Split()` and then
 using the new session to encrypt a single message.  This provides security for
 old keys against future compromises, and also allows cacheing old keys in case
 of out-of-order messages.

 * **DH ratcheting**: Ephemeral public keys can be exchanged and mixed into a
 "root" session by alternating `ReadEphemeral()` and `WriteEphemeral()` calls.
 This allows implementing an Axolotl-like ratchet, where receiving and sending
 sessions are derived from the root session via `Split()` calls.

7. Conventions
===============

The following conventions are recommended but not required:

 * **Protocol naming**:  The protocol name should consist of four
 underscore-separated fields that identify the ciphersuite, the handshake
 pattern, handling of application messages, and conventions.  Each of these name
 components should be unique within the scope of reuse for any long-term static
 key or pre-shared key.  Examples:

 `"Noise255/AES-GCM_BoxX_OneWayStreamVarLen_Conventional"`

 `"Noise448/ChaChaPoly_HandshakeXX_TwoStreamsVarLenStepping_Conventional"`

 * **Branch and length fields**:  All messages are preceded with a 1-byte branch
 number, then a 2-byte little endian unsigned integer indicating the length of
 the message.  Branch number zero indicates the default or "no branch" state.
 Any other value requires the recipient to process the branch as per Section
 4.3.  Payloads are kept small to support streaming APIs where data is
 incrementally authenticated.  Sending more data than fits in one payload
 requires a stream of messages (see bullet on "Stream termination").

 * **Explicit nonce fields**: If explicit nonces are being used for out-of-order
 application messages, then the 64-bit nonce should be encoded in little-endian,
 and sent after the branch number but before the length field.

 * **Stream termination**: If a protocol supports a variable-length stream of
 application messages, branch number 0 in an application message means more data
 is following in subsequent messages, and branch number 1 means this message
 contains the end of the stream.  Following Section 4.3, branch number 1 should
 trigger a `MixKey()` call with type 1.
 
 * **Padding**: All encrypted payload plaintexts end with a 2-byte little endian
 unsigned integer specifying the number of preceding bytes that are padding
 bytes.  Padding is applied to both handshake messages and application messages.
 This provides a consistent way to pad ciphertexts to a fixed length.

 * **Handshake extensions**:  The payload in any handshake message is parsed as
 a sequence of extensions, where each extension contains a 1-byte type field,
 followed by a 2-byte little endian unsigned integer indicating the length of
 the extension.  Unrecognized extensions are ignored by the recipient. 
 
 * **Error handling**: On any cryptographic or parsing failure, immediately
 erase all session contents and close any resources associated with the session
 (sockets, etc).


8. Ciphersuites
================

8.1. Noise255/ChaChaPoly and Noise448/ChaChaPoly
--------------------------------------------------

These are the default and recommended ciphersuites.

 * **`klen`** = 32

 * **`hlen`** = 32

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 or Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 or Curve448 function.
 
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

 * **`HASH(input)`**: `SHA2-256(intput)` 
 

8.2. Noise255/AES-GCM and Noise448/AES-GCM
--------------------------------------------

 * **`klen`** = 32

 * **`hlen`** = 32 
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 or Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 or Curve448 function.

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D.  The 96-bit nonce is formed by encoding 32
 bits of zeros followed by little-endian encoding of `n`.
 
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

 * **`HASH(input)`**: `SHA2-256(intput)` 

9. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be
catastrophic.  Implementations must carefully follow the rules for incrementing
nonces.   `SetNonce()` should only be called with extreme caution.

To avoid catastrophic key reuse, every party in a Noise protocol should send a
fresh ephemeral public key and perform a DH with it prior to sending any
encrypted data.  All patterns in Section 9 adhere to this rule.  

10. Rationale
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

Little-endian is preferred because:

 * Bignum libraries almost always use little-endian.
 * The standard ciphersuites use Curve25519, Curve448, and ChaCha20/Poly1305, which are little-endian.
 * Most modern processors are little-endian.

11. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

12. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Additional feedback on spec and pseudocode came from: Jason Donenfeld, Jonathan
Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


