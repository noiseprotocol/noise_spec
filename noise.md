
Noise
======

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-08-21
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key agreement.
Noise can describe protocols that consist of a single message as well as
interactive protocols.

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
agree on a shared secret.

A **descriptor** specifies the DH keys and DH operations that comprise a
handshake message.

A **pattern** specifies the sequence of descriptors that comprise a handshake.

A simple pattern might describe a one-way encrypted message from Alice to Bob.
A more complex pattern might describe an interactive handshake.

2.3.  After the handshake: application messages
------------------------------------------------

After the handshake messages each party will possess a shared secret key and can
send **application messages** which typically consist of encrypted payloads
without DH public keys.

Several operations can be used to control the encryption including: explicit
encryption nonces for out-of-order messages, "stepping" the shared key for
lightweight forward-security, and "fissioning" the shared key into separate keys
for duplex communications.

2.4. Key agreement
-------------------

Noise can implement handshakes where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that exist only during
the protocol.

2.5. DH functions and ciphersets
---------------------------------

A Noise protocol can be described abstractly in terms of its handshake pattern
and handling of application messages.

A set of **DH functions** and a **cipherset** instantiate the crypto functions
to give a concrete protocol.  The DH functions could use finite-field or
elliptic curve DH.  The cipherset specifies the symmetric-key functions.

3. Message format
==================

3.1. Handshake messages
------------------------

Every handshake message begins with a single `type` byte, which will be zero
unless a handshake branch is being taken, see !!!.

Following the `type` byte is a big-endian `uint16` `length` field describing
the number of following bytes in the message.

Following the `length` field will be one or more public keys.  Ephemeral public
keys are in the clear.  Static public keys will be encrypted if a secret key
has been negotiated.

Following the public keys is a `payload` field, which will be encrypted if a
secret key has been negotiated.

The `payload` will be composed of zero or more sections.  Each section begins
with a 1-byte `section type` and the sections appear in the payload in order,
with smallest types first.  Following the `section type` is a big-endian
`uint16` length field describing the number of following bytes in the section.
The meaning of different section types is left to the application, but could be
used for certificates, advertising supported versions, routing information,
etc.  Section 255 should be unused except for padding.  Unrecognized sections
should be ignored by the recipient.

3.2. Application messages
--------------------------

Every application message begins with a single `type` byte, which will be zero
unless this is the last application message in a session, in which case it's
set to 255.

If the protocol uses explicit nonces, then the `type` will followed by a 64-bit
nonce.

Following the `type` or `nonce` field is a big-endian `uint16` length field
describing the number of following bytes in the message.

Following the `length` field is an encrypted `payload` field, which contains
sections as described for handshake messages.  Section 0 should be used for the
primary stream of application data, and section 255 is only used for padding.
Unrecognized sections should be ignored by the recipient.


3. Sessions
============

A Noise session can be viewed as three layers:

 * DH functions and a cipherset provide low-level crypto functions.

 * A kernel object builds on the cipherset.  The kernel provides methods for
 mixing inputs into a secret key and using that key for encryption and
 decryption.

 * A session object builds on the kernel and DH functions and provides methods
 for handling messages.

The below sections describe each of these layers in turn.

3.1. DH algorithm and cipherset functions
------------------------------------------

Noise depends on the following **DH functions**:

 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

Noise also depends on the following **cipherset** functions:

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts `plaintext` using the cipher
 key `k` of 256 bits and a 64-bit unsigned integer nonce `n` which must be
 unique for the key `k`.  Encryption must be done with an "AEAD" encryption
 mode with the associated data `ad` and must add a 128-bit authentication tag
 to the end of the message.  This must be a deterministic function (i.e.  it
 shall not add a random IV; this ensures the `GETKEY()` function is
 deterministic).

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using a cipher
 key `k` of 256 bits, a 64-bit unsigned integer nonce `n`, and associated
 data `ad`.

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

3.2.  Kernel state and methods
-------------------------------

To simplify the descriptions and improve modularity, a session contains a
**kernel**.  The kernel can mix inputs into its internal state, and can encrypt
and decrypt data based on its internal state.  

A kernel contains the following state variables:

 * **`k`**: A symmetric key of 256 bits for the cipher algorithm specified
 in the cipherset.  This mixes together the results of all DH operations, and
 is used for encryption.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with `k`
 for encryption.

 * **`h`**: Either empty or 256 bits containtaining a hash output.  This
 value mixes together relevant handshake data, and is then authenticated by
 encryption.
 
A kernel responds to the following methods:

 * **`InitializeKernel()`**:  Sets `k` to all zero bytes, `n` to zero, and `h`
 to empty.

 * **`MixKey(type, data)`**:  Sets `k` to `KDF(GETKEY(k, n), type || data)`.  In
 other words, prepends `type` to `data` before applying the KDF. Then sets `n`
 to zero.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  In other words,
 replaces `h` by the hash of `h` with `data` appended.

 * **`ClearHash()`**: Sets `h` to empty.

 * **`SetNonce(nonce)`**:  Sets `n` to `nonce`.

 * **`StepKey()`**:  Sets `k` to `GETKEY(k, n)`.  Sets `n` to zero.

 * **`FissionKernel()`**:  Creates a new child kernel, with `n` set to 0 and `h`
 copied from this kernel.  Sets the child's `k` to the output of `GETKEY(k, n)`,
 and increments `n`.  Then sets its own `k` to the output of `GETKEY(k, n)` and
 sets `n` to zero.  Then returns the child.

 * **`Encrypt(plaintext)`**:  Calls `ENCRYPT(k, n, h, plaintext)` to get a
 ciphertext, then increments `n` and returns the ciphertext.

 * **`Decrypt(ciphertext)`**:  Calls `DECRYPT(k, n, h, ciphertext)` to get a
 plaintext, then increments `n` and returns the plaintext.

3.3.  Session state and methods
--------------------------------

Sessions contain a kernel object, plus the following state variables:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

A session responds to all of the kernel methods by forwarding them to the
kernel.  In addition, a session responds to the following initialization methods:

 * **`Initialize(name, static_keypair, preshared_key, premessages)`**:  
 
   * Calls `InitializeKernel()`.
   
   * Calls `MixKey(0, name)`.  
   
   * If `preshared_key` isn't empty then `MixKey(0, preshared_key)` is called.
   
   * If `static_keypair` isn't empty then `SetStaticKeyPair(preshared_key)` is
   called.  
   
   * All other variables are set to empty.

 * **`Fission()`**: Returns a new session by calling `FissionKernel()` on the
 kernel and copying the returned kernel and all session state into a new
 session.

For reading or writing messages, the following methods are used.  These methods
take a `buffer` of bytes that they either append to or read from.  They also
take a **descriptor**, which is a comma-separated string containing tokens from
the following list: "e, s, dhee, dhes, dhse, dhss".

 * **`WriteHandshakeMessage(buffer, descriptor, payload, padded_len)`**: Takes
 a byte buffer, a descriptor, and a payload which is an encoded set of zero or
 more sections.
 
    * Processes each token in the descriptor sequentially.  For "e" sets `e =
    GENERATE_KEYPAIR()` and appends the public key to the buffer.  For "s" if
    `HasKey() == True` appends `Encrypt(s)` to the buffer, otherwise appends
    `s`; in either case then calls `MixHash(s)`.  For "dh*xy*" calls `MixKey(0,
    DH(x, ry))`.

    * If `HasKey() == True` appends `Encrypt(payload)` to the buffer, otherwise
    appends `payload`; in either case then calls `MixHash(payload)`.  

    * Sets `buffer_len = len(buffer)`.  Prepends the `type` byte, then `uint16`
    encoding of `buffer_len`, to the buffer.

 * **`WriteApplicationMessage(buffer, payload, final)`**:  

   * Calls `ClearHash()`.

   * Appends `Encrypt(payload)` to the buffer.

   * Sets `buffer_len = len(buffer)`.  If `final == True` sets `type` byte to
   255, otherwise sets it to zero.  Prepends the `type` byte, then `uint16`
   encoding of `buffer_len`, to the buffer.

 * **`ReadHandshakeMessage(buffer, descriptor, handshake)`**:  Reads the
 `branch` byte and returns if not expected.  Processes each token in the
 descriptor sequentially.  For "e" sets `re` to the next `dhlen` bytes from the
 buffer.  For "s" reads the next `dhlen + 16` bytes from the buffer into `data`
 and sets `rs = Decrypt(data)` if `HasKey() == True`; otherwise reads the next
 `dhlen` bytes from the buffer into `rs`.  In either case, after setting `rs`
 calls `MixHash(rs)`.   For "dh*xy*" calls `MixKey(0, DH(y, rx))`.  After the
 descriptor is processed sets `payload = Decrypt(buffer)` if `HasKey() ==
 True`, otherwise sets `payload == buffer`.  Calls `MixHash(payload).`



4. Handshake patterns
======================

A pattern is a sequence of descriptors. Descriptors with right-pointing arrows
are for messages created and sent by the protocol initiator; with left-pointing
arrows are for messages sent by the responder.  All messsages described by the
pattern must be sent in order.  

Patterns must follow these security rules:  If a pattern has a single handshake
message, the first token in that message's descriptor must be "e", and the
second token must be "dhe*x*", where _x_ is a pre-known public key.  If a
pattern has more than one handshake message, then the initiating message must
begin with "e", and the response message must begin with "e, dhee".

The following is the minimal 2-message pattern.  It describes an unauthenticated
DH handshake:

      -> e
      <- e, dhee

Pre-messages are shown as descriptors prior to the delimiter "\-\-\-\-\-\-".
These messages aren't sent but are only used for their side-effect of calling
`MixHash()`.  

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral:

      <- s
      ------
      -> e, dhes 
      <- e, dhee

The following patterns represent the mainstream use of Noise.  Other patterns
can be defined in other documents.

5.1. One-way patterns
----------------------

The following patterns represent one-way messages from a sender to a recipient.
OneWayX is recommended for most uses.

     N  = no static key for sender
     K  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    OneWayN:
      <- s
      ------
      -> e, dhes

    OneWayK:
      <- s
      -> s
      ------
      -> e, dhes, dhss

    OneWayX:
      <- s
      ------
      -> e, dhes, s, dhss

5.2. Interactive patterns
--------------------------

The following 16 patterns represent protocols where the initiator and responder
exchange messages to agree on a shared key.  InteractiveXX is recommended for most
uses.

     N_ = no static key for initiator
     K_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder
     I_ = static key for inititiator immediately transmitted to responder
 
     _N = no static key for responder
     _K = static key for responder known to initiator
     _E = static key plus a semi-ephemeral key for responder known to initiator
     _X = static key for responder transmitted to initiator


    InteractiveNN:                      InteractiveKN:                 
      -> e                              -> s                       
      <- e, dhee                        ------                     
                                        -> e                       
                                        <- e, dhee, dhes           
                                             
    InteractiveNK:                      InteractiveKK:                 
      <- s                              <- s                       
      ------                            -> s                       
      -> e, dhes                        ------                     
      <- e, dhee                        -> e, dhes, dhss           
                                        <- e, dhee, dhes           
                                              
    InteractiveNE:                      InteractiveKE:                 
      <- s, e                           <- s, e                    
      ------                            -> s                       
      -> e, dhee, dhes                  ------                     
      <- e, dhee                        -> e, dhee, dhes, dhse     
                                        <- e, dhee, dhes           
                                                                     
    InteractiveNX:                      InteractiveKX:                 
      -> e                              -> s                       
      <- e, dhee, s, dhse               ------                     
                                        -> e                       
                                        <- e, dhee, dhes, s, dhse  
                            

    InteractiveXN:                      InteractiveIN:                   
      -> e                              -> e, s                      
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    InteractiveXK:                      InteractiveIK:                   
      <- s                              <- s                         
      ------                            ------                       
      -> e, dhes                        -> e, dhes, s, dhss          
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    InteractiveXE:                      InteractiveIE:                   
      <- s, e                           <- s, e                      
      ------                            ------                       
      -> e, dhee, dhes                  -> e, dhee, dhes, s, dhse    
      <- e, dhee                        <- e, dhee, dhes             
      -> s, dhse                                                     
                                       
    InteractiveXX:                      InteractiveIX:                  
      -> e                              -> e, s                     
      <- e, dhee, s, dhse               <- e, dhee, dhes, s, dhse                                
      -> s, dhse

5.3. Branching
---------------

Branching allows parties to alter the handshake pattern, ciphersets, or other
protocol characteristics on the fly.  For example: 

 * A server could choose which cipherset to support based on options offered
 by the client.

 * A client could choose whether to authenticate itself based on the server's
 response.

 * A client could attempt an abbreviated handshake based on cached information,
 and if this information is stale the server can fall back to a full handshake.

Branching requires:

 * Designating a particular handshake message as a branch message

 * Assigning branch numbers and names to the alternatives for the branch message
 (where branch number zero is the default, and other branches count up from
 there).

 * Providing some way to indicate the branch number to the recipient (see
 Section 8).

 * For each alternative, specifying whether it re-uses the session state or
 re-initializes the session.

If a non-zero branch is taken and session state is re-used, `MixKey(1, name)` is
called on the branch name.

If a non-zero branch is taken and session state is re-initialized, then the
branch message is treated as starting a new handshake, and the steps from 4.2
are performed, except `InitializeKernel()` is called in place of
`InitializeSession()` to allow previously exchanged public keys to be re-used.


6. Application messages
========================

Application messages can be sent in several ways:

 * **One-way stream**: One party sends a stream of messages.  For security
 reasons this is the only allowed method when using a one-way handshake.  

 * **Alternating stream**: Both parties strictly alternate messages, using a
 single session.

 * **Two streams**: Both parties send a stream of messages, using separate
 sessions.  In this case, `Fission()` is called with the initiator using the
 original session and the responder using the new session.

Out of order messages can be handled by prepending `n` as an **explicit nonce**
to each message.  The recipient will call `SetNonce()` on the explicit nonce.

Key updating techniques can be used within a stream:

 * **Stepping**: After sending a message, `StepKey()` is called to destroy
 the old key and replace it with a new one.  This provides security for old
 messages against future compromises.

 * **Message keys**: Each message is encrypted by calling `Fission()` and then
 using the new session to encrypt a single message.  This provides security for
 old keys against future compromises, and also allows cacheing old keys in case
 of out-of-order messages.

 * **DH ratcheting**: Ephemeral public keys can be exchanged and mixed into a
 "root" session.  This allows implementing an Axolotl-like ratchet, where
 receiving and sending sessions are derived from the root session via `Fission()`
 calls.

7. Protocol names
==================

Every protocol and branch requires its own name.  These names must be unique
within the scope of possible reuse for any long-term static key or pre-shared
key.

A Noise protocol or branch name should consist of seven underscore-separated
fields that identify the DH functions, the cipherset, the handshake pattern,
handling of application messages, conventions, and a unique name for the
application protocol.  Examples:

 `"Noise_Curve25519_AES-GCM_OneWayX_OneWayStream_Conventional_SpecExample1"`

 `"Noise_Curve448_ChaChaPoly_InteractiveXX_TwoStreamsStepping_Conventional_SpecExample2"`

8. Conventions
===============

The following conventions are recommended but not required:

 * **Explicit nonce fields**: If explicit nonces are being used for out-of-order
 application messages, then the 64-bit nonce should be encoded in little-endian,
 and sent after the branch number but before the length field.

 * **Error handling**: On any cryptographic or parsing failure, immediately
 erase all session contents and close any resources associated with the session
 (sockets, etc).


9. DH functions and ciphersets
===============================

9.1. The Curve25519 and Curve448 DH functions
----------------------------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 or Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 or Curve448 function.

9.2. The ChaChaPoly cipherset
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

 * **`HASH(input)`**: `SHA2-256(intput)` 
 

9.3. The AES-GCM cipherset
---------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D with 128-bit tags.  The 96-bit nonce is formed
 by encoding 32 bits of zeros followed by little-endian encoding of `n`.
 
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

10. Examples
============

**`Noise_Curve448_ChaChaPoly_OneWayN_OneWayStream_Conventional`:**

This protocol implements public-key encryption without sender authentication.
Because it uses a one-way handshake and one-way stream of application messages,
this represents a single stream of bytes from sender to recipient.  The initial
bytes encode a handshake message:

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 56-byte Curve448 ephemeral public key
 * Encrypted payload - minimum 18 bytes (2 for padding length, 16 for MAC; more if padding or handshake extensions are sent)

Following this are any number of application messages:

 * 1-byte zero branch number for application message
 * 2-byte length field for application message
 * Encrypted payload - minimum 18 bytes

The final application message is the same, except with branch number 255 instead of 0.

**`Noise_Curve25519_AES-GCM_InteractiveXX_TwoStreams_Conventional`:**

This protocol implements a mutual-authenticated interactive handshake, followed
by interactive data exchange.  The initiator's first handshake message is:

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 32-byte Curve25519 ephemeral public key
 * Payload - minimum 0 bytes (more if handshake extensions are sent)

The responder's handshake message is:

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 32-byte Curve25519 ephemeral public key
 * 48-byte encrypted Curve25519 static public key (+16 bytes for GCM MAC) 
 * Encrypted payload - minimum 18 bytes (2 for padding length, 16 for MAC; more if padding or handshake extensions are sent)

The initiator's final handshake message is: 

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 48-byte encrypted Curve25519 static public key (+16 bytes for GCM MAC) 
 * Encrypted payload - minimum 18 bytes 

Following this `Fission()` splits off a separate session so both parties can
send a stream of messages.  To indicate they have finished sending data they
each send a message with branch number 255.

**`Noise_Curve25519_AES-GCM_InteractiveIK_TwoStreams_Conventional`**

with branch to

**`Noise_Curve25519_AES-GCM_InteractiveXX_TwoStreams_Conventional`:**

This protocol is used when the client wants to run an abbreviated handshake
(InteractiveIK) and send some encrypted extensions in her first message.  If the
server has changed its static key and can't decrypt that message, it will branch
to InteractiveXX.  The initiator's first handshake message is:

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 32-byte Curve25519 ephemeral public key
 * 48-byte encrypted Curve25519 static public key (+16 bytes for GCM MAC) 
 * Encrypted payload - minimum 18 bytes 

The responder may continue with the IK handshake by returning branch zero:

 * 1-byte zero branch number of handshake message
 * 2-byte length field for the handshake message
 * 32-byte Curve25519 ephemeral public key
 * Encrypted payload - minimum 18 bytes 

Or the responder may switch to branch 1, and return the responder handshake
message from above.  If the receiver receives a branch 1 message, she
re-initializes the session with the branch name, and then sends the final
InteractiveXX handshake message. 


11. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be
catastrophic.  Implementations must carefully follow the rules for incrementing
nonces.   `SetNonce()` should only be called with extreme caution.

To avoid catastrophic key reuse, every party in a Noise protocol should send a
fresh ephemeral public key and perform a DH with it prior to sending any
encrypted data.  This is the rationale behind the security rules for patterns in
Section 4.1.

12. Rationale
=============

This section collects various design rationale:

Nonces are 64 bits in length because:

 * Some ciphers (e.g. Salsa20) only have 64 bit nonces
 * 64 bit nonces were used in the initial specification and implementations of ChaCha20, so Noise nonces can be used with these implementations.
 * 64 bits allows the entire nonce to be treated as an integer and incremented 
 * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if random nonces are acceptable.

The default ciphersets use SHA2-256 because:

 * SHA2 is widely available
 * SHA2-256 requires less state than SHA2-512 and produces a sufficient-sized output (32 bytes)
 * SHA2-256 processes smaller input blocks than SHA2-512 (64 bytes vs 128 bytes), avoiding unnecessary calculation when processing smaller inputs

The cipher key must be at least 256 bits because:

 * The cipher key accumulates the DH output, so collision-resistance is desirable

Little-endian is preferred because:

 * Bignum libraries almost always use little-endian.
 * The standard ciphersets use Curve25519, Curve448, and ChaCha20/Poly1305, which are little-endian.
 * Most modern processors are little-endian.

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


