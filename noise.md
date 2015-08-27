
Noise v1 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-08-26
 * **Revision:** 01 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key agreement.
Noise can describe protocols that consist of a single message as well as
interactive protocols.

2. Overview
============

2.1. Handshake messages: descriptors and patterns
--------------------------------------------------

A Noise protocol begins with a handshake phase where both parties send
**handshake messages** containing DH public keys and perform DH operations to
agree on a shared secret.

A **descriptor** specifies the DH public keys and DH operations that comprise a
handshake message.  A **pattern** specifies the sequence of descriptors that
comprise a handshake.

A pattern might describe a one-way encrypted message from Alice to Bob or an
interactive handshake.

2.2.  After the handshake: transport messages
----------------------------------------------

After the handshake messages each party will possess a shared secret key and
can send **transport messages** which consist of encrypted payloads.

2.3. Key agreement
-------------------

Noise can implement handshakes where each party has a static and/or ephemeral
DH key pair.  The static keypair is a long-term key pair that exists prior to
the protocol.  Ephemeral key pairs are short-term key pairs that are typically
used for a single handshake.

2.4. DH functions and ciphersets
---------------------------------

A Noise protocol is specified abstractly by its handshake pattern.

A set of **DH functions** and a **cipherset** instantiate the crypto functions
to give a concrete protocol.  The DH functions could use finite-field or
elliptic curve DH.  The cipherset specifies the symmetric-key functions.

3. Message format
==================

3.1. Handshake messages
------------------------

    uint8 type;
    uint16 length;
    // 1 or more of
    //   byte pubkey[dhlen] or 
    //   byte encrypted_pubkey[dhlen+16];
    byte payload[length - pubkeys_length];

Every handshake message begins with a single `type` byte, which is typically
zero.  Non-zero values can be used to indicate new versions or alternate
messages.

Following the `type` byte is a big-endian `uint16` `length` field describing
the number of following bytes in the message.

Following the `length` field will be one or more public keys.  Ephemeral public
keys are in the clear.  Static public keys will be encrypted if a secret key
has been negotiated.

Following the public keys is a `payload` field, which will be encrypted if a
secret key has been negotiated.  The payload may contain certificates, routing
information, advertisements for supported features, or anything else.

3.2. Transport messages
--------------------------

    uint16 length;
    byte payload[length];

Every transport message begins with a big-endian `uint16` length field
describing the number of following bytes in the encrypted payload.  The first
byte of the decrypted payload will be a 1 if this is the final message, 0
otherwise.

3. Sessions
============

A Noise session can be viewed as three layers:

 * **DH functions** and a **cipherset** provide low-level crypto functions.

 * A **kernel object** builds on the cipherset.  The kernel mixes inputs into a
 secret key and uses that key for encryption and decryption.

 * A **session object** builds on the kernel and DH functions.

The below sections describe each of these layers in turn.

3.1. DH algorithm and cipherset functions
------------------------------------------

Noise depends on the following **DH functions** and constants:

 * **`dhlen`** = A constant specifying the size of public keys in bytes.
 
 * **`GENERATE_KEYPAIR()`**: Generates a new DH keypair.

 * **`DH(privkey, pubkey)`**: Performs a DH calculation and returns an output
 sequence of bytes. 

Noise depends on the following **cipherset** functions:

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

A kernel can mix inputs into its internal state, and can encrypt and decrypt
data based on its internal state.  A kernel contains the following state
variables:

 * **`k`**: A symmetric key of 256 bits for the cipher algorithm specified in
 the cipherset.  This mixes together the results of all DH operations, and is
 used for encryption.

 * **`n`**: A 64-bit unsigned integer nonce.  This is used along with `k`
 for encryption.

 * **`h`**: Either empty or 256 bits containing a hash output.  This is used as
 "associated data" for encryption.
 
A kernel responds to the following methods:

 * **`Initialize()`**:  Sets `k` to all zeros, `n` to zero, and `h` to all zeros.
 
 * **`ClearHash()`**: Sets `h` to empty.

 * **`MixKey(data)`**:  Sets `k` to `KDF(GETKEY(k, n), data)`.  Then sets `n`
 to zero.

 * **`MixHash(data)`**:  Sets `h` to `HASH(h || data)`.  In other words,
 replaces `h` by the hash of `h` with `data` appended.

 * **`Split()`**:  Creates two new child kernels by calling `GETKEY(k, n)` to
 get the first child's `k`, then incrementing `n` and calling `GETKEY(k, n)` to
 get the second child's `k`.  The children have `n` set to zero and `h` set to
 the parent's value. The two children are returned.

 * **`Encrypt(plaintext)`**:  Calls `ENCRYPT(k, n, h, plaintext)` to get a
 ciphertext, then increments `n` and returns the ciphertext.

 * **`Decrypt(ciphertext)`**:  Calls `DECRYPT(k, n, h, ciphertext)` to get a
 plaintext, then increments `n` and returns the plaintext.

3.3.  Session object usage
--------------------------------

A session object encapsulates the state variables and methods for executing a
Noise protocol.

To execute a Noise protocol you `Initialize()` a session, then call
`WriteHandshakeMessage()` and `ReadHandshakeMessage()` using successive
descriptors from the protocol's handshake pattern until the handshake is
complete.

After the handshake is complete you call `EndHandshake()`, which returns two
new sessions, the first for transport messages from initiator to responder, and
the second for messages in the other direction.

Then you call `WriteTransportMessage()` and/or `ReadTransportMessage()` on the
session(s) until finished communicating.

3.4. Session state and methods 
------------------------------

Sessions contain the following state variables:

 * **`kernel`**: Kernel object that provides symmetric crypto.

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

 * **`dummy_s, dummy_rs`**: Booleans that record whether `s` and `rs` are "dummy
 values".

 * **`has_key`**: Boolean that records whether the kernel has a secret key.

A session responds to the following methods:

 * **`Initialize(new_kernel, name, preshared_key, static_keypair,
   preshared_ephemeral_keypair)`**: Takes a kernel object.  Also
   takes a protocol `name` and `preshared_key` which are both variable-length
   byte sequences (the `preshared_key` may be empty).  Also takes optional
   static and "pre-shared ephemeral" keypairs.
 
   * Sets `kernel` to `new_kernel`.  Calls `kernel.Initialize()`.
   
   * Calls `kernel.MixKey(name || 0x00 || preshared_key)`.

   * If `preshared_key` isn't empty then sets `has_key` to `True`, otherwise
   sets it to `False`.
  
   * Sets `s` to `static_keypair` (which may be empty).

   * Sets `e` to `preshared_ephemeral_keypair` (which may be empty).

   * Sets `rs` and `re` to empty.

   * Sets `dummy_s` and `dummy_rs` to `False`.

 * **`WriteHandshakeMessage(buffer, descriptor, type, payload)`**: Takes an empty
 byte buffer, a descriptor which is some sequence of the tokens from "e, s,
 dhee, dhes, dhse, dhss", a `type` byte, and a `payload`.
 
    * Processes each token in the descriptor sequentially:
      * For "e":  Sets `e = GENERATE_KEYPAIR()` and appends the public key to the buffer.  
      * For "s":  If `s` is empty copies `e` to `s` and sets `dummy_s` to `True`. If `has_key == True`
      appends `kernel.Encrypt(s)` to the buffer, otherwise appends `s`.  Then
      calls `kernel.MixHash(s)`.  
      * For "dh*xy*" calls `kernel.MixKey(DH(x, ry))` and sets `has_key` to True.

    * If `has_key == True` appends `kernel.Encrypt(payload)` to the
    buffer, otherwise appends `payload`.  Then calls `kernel.MixHash(payload)`.  

    * Sets `buffer_len` to the length in bytes of `buffer`.  Prepends the
    `type` and `uint16` encoding of `buffer_len` to the buffer.

 * **`ReadHandshakeMessage(buffer, descriptor)`**: Takes a byte buffer
 containing a message, and a descriptor, and returns a payload.

    * Skips the first byte (which may be used by the caller to select the right
    descriptor).

    * Checks that the next 16 bits of length field are consistent with the size
    of the buffer.

    * Processes each token in the descriptor sequentially:
      * For "e" sets `re` to the next `dhlen` bytes from `buffer`.  
      * For "s" if `has_key == True` sets `rs` to the output from calling `kernel.Decrypt()` on the next
        `dhlen + 16` bytes from the buffer, otherwise sets `rs` to the next
        `dhlen` bytes from `buffer`. Then calls `kernel.MixHash(rs)`.  If `rs == re` sets `dummy_rs` to `True`.  
      * For "dh*xy*" calls `kernel.MixKey(DH(y, rx))` and sets `has_key` to
        True.

    * If `has_key == True` sets `payload` to the output from calling
    `kernel.Decrypt()` on the rest of the buffer, otherwise sets `payload` to
    the remainder of the buffer.  Then calls `kernel.MixHash(payload)`.  

 * **`EndHandshake()`**:  Sets `e` and `re` to empty, and calls
   `kernel.ClearHash()`.  If `dummy_s` is `True` sets `s` to empty.  If
   `dummy_rs` is `True` sets `rs` to empty.  Then returns two new sessions by
   calling `kernel.Split()` and copying the returned kernels and all session
   state into the new sessions.  Then erases all data from the current session.

 * **`WriteTransportMessage(buffer, final, payload)`**:  Takes an empty byte
 buffer, a `final` boolean indicating whether this is the final transport
 message in the session, and a payload.

   * If `final == True` prepends a byte with value 1 to payload, otherwise
     prepends a byte with value 0.

   * Writes a big-endian `uint16` encoding of payload length + 16 to `buffer`.

   * Writes `kernel.Encrypt(payload)` to `buffer`.

 * **`ReadTransportMessage(buffer)`**:  Takes a byte buffer containing a
 message.  Returns a payload and `final` boolean indicating whether this is the
 final transport message in the session.

   * Checks that the first 16 bits of length field are consistent with the size
   of `buffer`.

   * Sets `payload` to `kernel.Decrypt()` on the rest of `buffer`.  

   * If the first byte of `payload` is 1 then sets `final = True`, otherwise sets
   `final = False`.  Removes the first byte from `payload`.

   * Returns `payload` and `final`.


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

The following patterns represent the mainstream use of Noise.  Other patterns
can be defined in other documents.

4.1. One-way patterns
----------------------

The following patterns represent "one-way" messages from a sender to a
recipient.

     N  = no static key for sender
     S  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    N:
      <- s
      ------
      -> e, dhes

    S:
      <- s
      -> s
      ------
      -> e, dhes, dhss

    X:
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


    NN:                              SN:                 
      -> e                             -> s                       
      <- e, dhee                       ------                     
                                       -> e                       
                                       <- e, dhee, dhes           
                                             
    NS:                              SS:                 
      <- s                             <- s                       
      ------                           -> s                       
      -> e, dhes                       ------                     
      <- e, dhee                       -> e, dhes, dhss           
                                       <- e, dhee, dhes           
                                              
    NE:                              SE:                 
      <- s, e                          <- s, e                    
      ------                           -> s                       
      -> e, dhee, dhes                 ------                     
      <- e, dhee                       -> e, dhee, dhes, dhse     
                                       <- e, dhee, dhes           
                                                                     
    NX:                              SX:                 
      -> e                             -> s                       
      <- e, dhee, s, dhse              ------                     
                                       -> e                       
                                       <- e, dhee, dhes, s, dhse  
                            

    XN:                              IN:                   
      -> e                             -> e, s                      
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    XS:                              IS:                   
      <- s                             <- s                         
      ------                           ------                       
      -> e, dhes                       -> e, dhes, s, dhss          
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    XE:                              IE:                   
      <- s, e                          <- s, e                      
      ------                           ------                       
      -> e, dhee, dhes                 -> e, dhee, dhes, s, dhse    
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                       
    XX:                              IX:                  
      -> e                             -> e, s                     
      <- e, dhee, s, dhse              <- e, dhee, dhes, s, dhse                                
      -> s, dhse

4.3. Dummy statics
--------------------------

Patterns where one party sends their static public key allow that party to opt
out of authenticating themselves.  If that party sets their static public key
equal to their ephemeral public key, this signals to the other party that a
distinct static public key does not exist.

4.3. Re-initialization 
------------------------

The `type` field in handshake messages can be used to trigger **session
re-initialization**.  This allows parties to alter handshake patterns on the
fly.

To allow re-initialization specify a non-zero `type` value for a particular
handshake message, the arguments to be used for `session.Initialize()`, and
the new handshake pattern to be used when this `type` is sent.

5. Protocols and names
=======================

5.1. Simple and compound protocols
-----------------------------------

A **simple protocol** supports a single handshake pattern, and is named for
that pattern (`Noise_X`, `Noise_NX`, `Noise_IE`, etc).

A protocol that uses the handshake type field to switch handshake patterns is a
**compound protocol**, and must be assigned a specific name.  Every branch
taken by this protocol is also assigned its own name that contains the protocol
name as a prefix.  

This document defines a single compound protocol (`Noise_Pipe`) with branch
names (`Noise_PipeXX`, `Noise_PipeIS`, and `Noise_PipeXXfromIS`).

All of the above are **abstract names**.  To produce a **concrete name** you
add name fields for the DH functions and cipherset (`Noise_X_25519_ChaChaPoly`,
`Noise_Pipe_25519_AESGCM`, `Noise_PipeXXfromIS_448_AESGCM`, etc.)

5.2. Noise Pipe
----------------

The **`Noise_Pipe`** protocol supports a "full" handshake `XX`.  An abbreviated
or "zero-round-trip" handshake `IS` is also supported via handshake
re-initialization:

 * If `type == 0` in the initiator's first handshake message then that message
 is an `XX` handshake using the name `Noise_PipeXX`.

 * If `type == 1` in the initiator's first handshake message then that message
 is an abbreviated `IS` handshake using the name `Noise_PipeIS`.

 * If `type == 1` in the responder's first `IS` response then the responder
 failed to authenticate the `IS` message (perhaps due to a static key change)
 and is falling back to `XX`, using name `Noise_PipeXXfromIS`.  The sender and
 responder will re-initialize, the responder using the first message's
 ephemeral ("e") turned into a pre-message.

Encrypted data sent in the first `IS` message is susceptible to replay attacks,
and also loses forward security and authentication if the responder's static
private key is compromised.  The abbreviated handshake's payload should only be
used for data where this reduction in security is acceptable.

The below patterns are annotated to show the message types for the regular,
abbreviated, and fallback cases:

    Noise_Pipe (XX):  
      0 -> e
      0 <- e, dhee, s, dhse  
      0 -> s, dhse

    Noise_PipeIS:                   
      <- s                         
      ------
      1 -> e, dhes, s, dhss          
      0 <- e, dhee, dhes             
                                        
    Noise_Pipe_XXfromIS:                   
      <- s                         
      ------
      1 -> e, dhes, s, dhss          

      (re-initialize, responder handles initiator's "e" as pre-message)

      1 <- e, dhee, s, dhse
      0 -> s, dhse


6. DH functions and ciphersets
===============================

6.1. The 25519 DH functions
----------------------------

 * **`dhlen`** = 32
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 function.

6.2. The 448 DH functions
--------------------------

 * **`dhlen`** = 56
 
 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve448 function.

6.2. The ChaChaPoly cipherset
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
 

6.3. The AESGCM cipherset
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


7. Security Considerations
===========================

This section collects various security considerations:

Reusing a nonce value for `n` with the same key `k` for encryption would be
catastrophic.  Implementations must carefully follow the rules for incrementing
nonces.   

To avoid catastrophic key reuse, every party in a Noise protocol should send a
fresh ephemeral public key and perform a DH with it prior to sending any
encrypted data.  This is one rationale behind the patterns in Section 4.

8. Rationale
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

The cipher key must be 256 bits because:

 * The cipher key accumulates the DH output, so collision-resistance is desirable

Big-endian is preferred because:

 * While it's true that bignum libraries, Curve25519, Curve448, and
 ChaCha20/Poly1305 use little-endian, these will likely be handled by
 specialized libraries.
 * The Noise length fields, on the other hand, are more likely to be handled by
 network parsing code where big-endian "network byte order" is more
 traditional.


9. IPR
========

The Noise specification (this document) is hereby placed in the public domain.

10. Acknowledgements
=====================

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike, Christian Winnerlein, and Hugo Krawzcyk provided feedback on
earlier versions of the key derivation.

Additional feedback on spec and pseudocode came from: Jason Donenfeld, Jonathan
Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


