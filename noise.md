
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
used for versioning.  

Prologue data is authenticated but ignored by default, so version numbers and
other data can be added into the prologue.  Older implementations that don't
recognize these fields will ignore them.   

2.3. Key agreement
-------------------

Noise can implement protocols where each party has a static and/or ephemeral DH
key pair.  The static keypair is a longer-term key pair that exists prior to the
protocol.  Ephemeral key pairs are short-term key pairs that are created and
destroyed during the protocol.

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

All other variables are set to empty.


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
 requesting a different ciphersuite or protocol - however the details of this
 negotation is out of scope).

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
recipient.  The descriptor for the message is given, and whether the message
requires initialization with only the recipient's public key (`rs`) or also the
sender's key pair (`s`).

    Box naming:
     N  = no static key for sender
     K  = static key for sender known to recipient
     X  = static key for sender transmitted to recipient

    BoxN:
      <- s
      -----
      -> e, dhes

    BoxK:
      <- s
      -----
      -> e, dhes, dhss

    BoxX:
      <- s
      -----
      -> e, dhes, s, dhss

Handshake protocols
--------------------

The following "Handshake" protocols represent handshakes where the initiator and
responder exchange messages.

    Handshake naming:

     N_ = no static key for initiator
     X_ = static key for initiator transmitted to responder without forward secrecy
     F_ = static key for initiator transmitted to responder with forward secrecy 

     _N = no static key for responder
     _K = static key for responder known to initiator
     _F = static key for responder transmitted to initiator with forward secrecy

    HandshakeNN:
      -> e
      <- e, dhee

    HandshakeNK:
      <- s
      -> e, dhes 
      <- e, dhee

    HandshakeNF:
      -> e
      <- e, dhee, s, dhse


    HandshakeXK:
      <- s
      -----
      -> e, dhes, s, dhss
      <- e, dhee, dhes


    HandshakeFK:
      <- s
      -----
      -> e, dhes
      <- e, dhee
      -> s, dhse 

    HandshakeFF:
      -> e
      <- e, dhee, s, dhse
      -> s, dhse





BoxSS                     sAuth* rAuth* (* = not KCI-resistant)
BoxNS           sFS              rAuth   -
BoxXS           sFS       sAuth* rAuth   sIDhide
BoxNE           sFS rFS          rAuth   -
BoxXE           sFS rFS   sAuth  rAuth   sIDhide

For handshakes, I only show messages up to the point that features
"stabilize", all subsequent messages in same direction have same
properties:

HandshakeNX->                            -
HandshakeNX<-   sFS rFS   sAuth          sIDhide* (* = anyone can solicit)
HandshakeNX->   sFS rFS          rAuth   -

HandshakeXX->
HandshakeXX<-   sFS rFS   sAuth          sIDhide*
HandshakeXX->   sFS rFS   sAuth  rAuth   sIDhide
HandshakeXX<-   sFS rFS   sAuth  rAuth   sIDhide*

HandshakeNS->   sFS              rAuth   -
HandshakeNS<-   sFS rFS   sAuth          sIDhide
HandshakeNS->   sFS rFS          rAuth   -

HandshakeXS->   sFS              rAuth   -
HandshakeXS<-   sFS rFS   sAuth          sIDhide
HandshakeXS->   sFS rFS   sAuth  rAuth   sIDhide
HandshakeXS<-   sFS rFS   sAuth  rAuth   sIDhide

HandshakeNE->   sFS rFS          rAuth   -
HandshakeNE<-   sFS rFS   sAuth          sIDhide

HandshakeXE->   sFS rFS   sAuth  rAuth   sIDhide
HandshakeXE<-   sFS rFS   sAuth  sAuth   sIDhide


4. Algorithms
==============

4.1. Ciphersuite variables
---------------------------

    SUITE_NAME = ? # 24-byte string uniquely naming the ciphersuite
    K_LEN = Length of PRF key in bytes
    OK_LEN = Length of output key in bytes


    GENERATE_KEY():
        # Returns a DH keypair

    DH(privkey, pubkey):
        # Calculates a DH result.
        # Returns a DH secret of length DH_LEN.

    ENCRYPT(cc, plaintext, authtext):
        # Takes a cipher context, some additional authenticated data, and plaintext.
        # Returns an "authenticated encryption" ciphertext of length equal to 
        # plaintext plus MAC_LEN.
        # Modifies the value of 'cc'.

    PRF(k, input):
        # Takes a PRF key and some input data and returns a new PRF key and output key.

    HASH(h, input):
        # Takes a hash context and some input data, and hashes the input data.  The eventual
        # value of the hash context is the hash of all input data.

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

2.1. PRF chains
----------------

A PRF is a "pseudorandom function" which takes a secret key and some input data
and returns output data. The output data is indistinguishable from random
provided the key isn't known.  HMAC-SHA2-512 is an example.

We use the term "PRF chain" when some of the output from a PRF is used as an
"output key", and some is used as a new PRF key to process another input.  The
below diagram represents a PRF chain processing inputs `i0...i2` and producing
output keys `ok0...ok2`, with a starting PRF key `k0` and a final PRF key `k3`:

                                     k0
                                i0 ->|
                                     v
                                     k1 ok0
                                i1 ->|
                                     v
                                     k2 ok1
                                i2 ->|
                                     v
                                     k3 ok2

                           (k1, ok0) = PRF(k0, i0)
                           (k2, ok1) = PRF(k1, i1)
                           (k3, ok2) = PRF(k2, i2)t
