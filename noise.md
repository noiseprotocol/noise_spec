
Noise
======

 * **Author:** Trevor Perrin (curves @ trevp.net)
 * **Date:** 2015-06-12
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for DH-based crypto protocols.  Noise can describe
protocols that consist of a single message as well as interactive protocols.

Noise messages are described in a language that specifies the exchange of DH
public keys and DH calculations.  The DH outputs are accumulated into a session
state.  This allows the construction of multi-message protocols.

The resulting protocols can be instantiated based on ciphersuites that fill in
the details of the DH calculation and other crypto primitives.


2. Overview
============

2.1. Messages, sessions, and descriptors
-----------------------------------------

Noise messages are ciphertext objects exchanged between parties.  Noise messages
can be **created** and **consumed**.

Each Noise party will have a **session** which contains the state used to
process messages.  Each Noise message corresponds to a **descriptor** which
describes the contents of a message and the rules for processing it.

Creating a message requires **prologue** and **payload** data, a **descriptor**,
and a **session**.  The output is a **message** and an updated **session**.

Consuming a message requires a **message**, a **descriptor**, and a **session**.
The output is **prologue** and **payload** data, and an updated **session**.

2.2. Prologue and payload
--------------------------

Noise messages will contain prologue and payload data.  The payload is typically
(but not always) encrypted.  The prologue is an unencrypted header that can be
used for version and feature negotiation.  

Prologue data is authenticated but ignored by default, so version numbers and
other data can be added into the prologue.  Older implementations that don't
recognize these fields will ignore them.   

2.3. Key agreement
-------------------

Noise can implement protocols where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that are created and
destroyed during the protocol.

The parties may have prior knowledge of each other's static public keys, before
executing a Noise protocol.  This is represented by "pre-messages" containing
these public keys that both parties use to initialize their session state.

3. Crypto functions
====================

Noise depends on the following functions, which are supplied by a **ciphersuite**:

 * **DH(privkey, pubkey):** Performs a DH or ECDH calculation and returns an
 output sequence of bytes. 
 
 * **ENCRYPT(k, authtext, plainttext), DECRYPT(k, authtext, ciphertext):**
 Encrypts or decrypts data using the cipher key `k`, using authenticated
 encryption with the additional authenticated data `authtext`.  Returns an
 updated cipher key that may be used for subsequent calls to encrypt, so the
 encryption should be randomized or use an IV that's stored as part of the key.

 * **KDF(k, input):** Takes a cipher key and some input data and returns a new
 cipher key.  The KDF should be a PRF when keyed by `k`.  The same `k` may be
 used in a call to `KDF` and to `ENCRYPT` or `DECRYPT`, so these functions
 should use nonces or internal key derivation steps to make this secure.

 * **HASH(input):** Hashes some input and returns the output.

4. Structures
==============

4.1. Session variables
-----------------------

A Noise session contains several variables.  Any of these variables may be empty.

Each session has two variables for DH (or ECDH) key pairs:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

Each session has two variables for DH (or ECDH) public keys:

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

The following variables are used for symmetric cryptography:

 * **`k`**: A symmetric key for the cipher algorithm specified in the
 ciphersuite.  

 * **`h`**: A hash output from the hash algorithm specified in the ciphersuite.

4.2. Messages
--------------

A Noise message has the following structure:

 * A 1-byte prologue length.

 * 0-255 bytes of prologue data.

 * A sequence of public keys (perhaps encrypted), as determined by the message's
 descriptor.

 * A message payload which is either encrypted or in clear.


5. Processing
--------------

5.1. Reading and writing
-------------------------

While processing messages, a Noise party will perform writes into the message
(for a creator) or reads from the message (for a consumer).  While processing a
message, the processor will maintain a local pointer to the last byte written
(or read), and will write (or read) after that, and advance the pointer.

"Clear" reads and writes are performed without encryption.  "Encrypted" reads
and writes will encrypt or decrypt the value using `k` if `k` is non-empty, and
replace `k`.  When encrypting or decrypting, the additional authenticated data
(`authtext`) is set to `h` followed by all preceding bytes of the message.

5.1. Descriptors
-----------------

A descriptor is a comma-separated list containing some of the following tokens.
The tokens describe the sequential actions taken by the creator or consumer of a
message.

 * **`e`**: The creator generates an ephemeral key pair, stores it in her `e`
 variable, and then performs a clear write of her ephemeral public key.  The
 consumer performs a clear read of the ephemeral public key into her `re`
 variable. 

 * **`s`**: The creator performs an encrypted write of her static public key.
 The consumer performs an encrypted read of the static public key into her `rs`
 variable.

 * **`dhss, dhee, dhse, dhes`**: A DH calculation is performed between the
 creator's static or ephemeral key (specified by the first character) and the
 consumer's static or ephemeral key (specified by the second character).  The
 output is used to update `k` by calculating `k = KDF(k, output)`.

5.2. Session operations
------------------------

A Noise session supports the following operations:

 * **Initialize:** Initializes a session.
 
 * **Create message:** Takes a prologue and payload (either of which may be
 empty) and a descriptor and returns a message.

 * **Consume message:** Takes a message and descriptor and returns a prologue
 and payload.

 * **Split:** Takes a session and returns two derived sessions.  This is called
 at the end of a handshaking protocol to create sending and receiving sessions for
 each party and delete ephemeral private keys.

5.3. Initializing a session
----------------------------

Takes an ASCII label and writes its bytes into `h` sequentially, zero-filling
any unused bytes.  The label should be unique to the particular ciphertext,
descriptor, and protocol. 

Also takes an optional key pair for the `s` variable.  All other variables are
set to empty.

5.3. Creating a message
------------------------

On input of some prologue and payload data and a descriptor, a message is
constructed with the following steps:

 1) The length of the prologue data is written in the first byte, followed by
 prologue data.  This write is performed in clear.

 2) The descriptor is processed sequentially, as described above.

 3) The payload is written into the message via an encrypted write (so
 ciphertext is written if `k` is not empty).

 4) If the descriptor was not empty, `h` is set to `HASH(h || message)`.

5.4. Consuming a message
-------------------------

On input of a message and descriptor, the message is consumed with the following steps:

 1) The prologue data is returned via some callback.  The caller can examine the
 prologue data to see if the message is requesting different processing (e.g.,
 requesting a different ciphersuite or protocol - the details of this negotation
 is out of scope).


 2) The descriptor is processed sequentially, as described above.

 3) The payload is read via an encrypted read (so the ciphertext is decrypted if
 `k` is not empty).

 4) If the descriptor was not empty, `h` is set to `HASH(h || message)`.

5.5. Splitting a session
-------------------------

A session is split with the following steps:

 1) All private keys are deleted from the session.

 2) The session is copied into two child sessions.

 3) The first child's `k` is set to `k = KDF(k, zeros)` where `zeros` is a
 string of length equal to a DH output filled with zeros.  The second child's
 `k` is set the same way except using a string filled with 0x01 bytes.

The two children are returned.  Splitting typically happens after a handshake
protocol is complete.  The initiator of a protocol should use the first session
for sending messages, and the second session for receiving them.

6. Protocols
=============

6.1. Box protocols
-------------------

The following "Box" protocols represent one-shot messages from a sender to a
recipient.  Each protocol is given a name, and then described via a sequence of
descriptors.  Descriptors with right-pointing arrows are for messages created
and sent by the protocol initiator; with left-pointing arrows are for messages
sent by the responder.

Pre-messages are used to represent prior knowledge of static public keys.  These
are shown as descriptors prior to the delimiter "---".  These messages are not
part of the protocol proper, but the parties should create and consume them as
if they were.

    Box naming:
     N  = no static key for sender
     K  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    BoxN:
      <- s
      ---
      -> e, dhes

    BoxK:
      <- s
      -> s
      ---
      -> e, dhes, dhss

    BoxX:
      <- s
      ---
      -> e, dhes, s, dhss

6.2. Handshake protocols
-------------------------

The following "Handshake" protocols represent handshakes where the initiator and
responder exchange messages.

    Handshake naming:

     N_ = no static key for initiator
     K_ = static key for initiator known to responder
     X_ = static key for initiator transmitted to responder

     _N = no static key for responder
     _K = static key for responder known to initiator
     _X = static key for responder transmitted to initiator


    HandshakeNN:
      -> e
      <- e, dhee

    HandshakeNK:
      <- s
      ---
      -> e, dhes 
      <- e, dhee

    HandshakeNX:
      -> e
      <- e, dhee, s, dhse


    HandshakeKN:
      -> s
      ---
      -> e
      <- e, dhee, dhes
    
    HandshakeKK:
      <- s
      -> s
      ---
      -> e, dhes
      <- e, dhee, dhes

    HandshakeKX:
      -> s
      ---
      -> e
      <- e, dhee, dhes, s, dhse


    HandshakeXN:
      -> e
      <- e, dhee
      -> s, dhse

    HandshakeXK:
      <- s
      -----
      -> e, dhes
      <- e, dhee
      -> s, dhse 

    HandshakeXX:
      -> e
      <- e, dhee, s, dhse
      -> s, dhse


The above protocols perform 2 or 3 DHs, and are suitable for most purposes.
Below are some 4-DH variants.

`KX_quad` and `XX_quad` tack on a static-static DH to add some forward secrecy
in case both ephemeral private keys are bad.  `KK_quad` and `XK_quad` perform
the static-static DH in the first message, so allow the client to send some
initial data protected under the static-static DH.

    HandshakeKK_quad:
      <- s
      -> s
      ---
      -> e, dhes, dhss
      <- e, dhee, dhes

    HandshakeKX_quad:
      -> s
      ---
      -> e
      <- e, dhee, dhes, s, dhse, dhss

    HandshakeXK_quad:
      <- s
      -----
      -> e, dhes, s, dhss
      <- e, dhee, dhes

    HandshakeXX_quad:
      -> e
      <- e, dhee, s, dhse
      -> s, dhse, dhss


7. Ciphersuites
================

7.1. Noise255 and Noise448
---------------------------

These are the default and recommended ciphersuites.

 * **DH(privkey, pubkey):** Curve25519 (Noise255) or Goldilocks (Noise448).
 
 * **ENCRYPT(k, authtext, plainttext), DECRYPT(k, authtext, ciphertext):**
 AEAD\_CHACHA20\_POLY1305 from RFC 7539.  `k` is a 44-byte value consisting of
 32 bytes key and 12 bytes nonce.  `k` is updated by inverting each bit of the
 nonce and then calculating a 64-byte ChaCha20 output with the previous key and
 new nonce, then taking the first 44 bytes as the new key and nonce.

 * **KDF(k, input):** `HMAC-SHA2-512(k, input)`.  The first 44 bytes of the
 output are used as the new `k`.
 
 * **HASH(input):** `SHA2-512`.

7.2. AES256-GCM ciphersuites
-----------------------------

These ciphersuites are named Noise255/AES256-GCM and Noise448/AES256-GCM.  The
DH, and HASH functions are the same as above.

Encryption uses AES-GCM but only increments the counter (the last 64 bits of the
96-bit nonce, treated as a big-endian integer), instead of replacing the entire
`k`.  (This is due to AES-GCM's lack of key agility).

The KDF is the same as above except the first 32 bits of the nonce are inverted,
the remainder are set to zero, and then 48 bytes of AES-CTR keystream are
generated.  These are then used as the key for KDF(key, input).  This ensures
that the ENCRYPT and KDF operations never operate on the same key.

# IPR

The Noise specification (this document) is hereby placed in the public domain.

# Acknowledgements

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al.,
and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike and Christian Winnerlein assisted in designing the key
derivation process. The Noise KDF has some similarity with HKDF from Hugo
Krawzcyk, who also provided some feedback.

Additional feedback on spec and pseudocode came from: Jonathan Rudenberg,
Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.


