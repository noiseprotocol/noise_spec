
Noise
======

 * **Author:** Trevor Perrin (curves @ trevp.net)
 * **Date:** 2015-03-16
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for DH-based crypto protocols. 

Messages are described in a "descriptor" language that allows exchange of DH
public keys and DH calculations.  The DH shared secrets are accumulated into a
"PRF chain" that produces output keys based on all previous shared secrets.

The resulting protocols can be instantiated based on various ciphersuites that
fill in the details of the DH calculation and other crypto primitives.


2. Overview
============

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

2.2. Noise session state 
-------------------------

A Noise protocol consists of a series of messages between two parties.  Each
party has a session state which is updated as it processes messages.

The state contains DH variables:

 * `e`: The local ephemeral key pair

 * `s`: The local static key pair 

 * `re`: An ephemeral public key for the remote party

 * `rs`: The remote party's static public key

The state contains variables for a PRF chain:

 * `k`: A PRF key for a PRF chain 

 * `ok`: An output key from the PRF chain, for use in encrypting data

The state also contains a hash context that hashes all sent and received
message data.  

 * `h`: A hash context 

2.3. Noise descriptors
-----------------------

A Noise message is described by a "descriptor", which is a comma-separated list
containing some of the following tokens.  The tokens describe the sequential
actions taken by a sender or receiver of the message:

 * `e`: The sender generates an ephemeral public key, stores it in their `e`
variable, and then appends it to the message in cleartext.  The receiver reads
the value into their `re` variable. 

 * `s`: The sender appends their static public key.  If there's a non-empty
`ok` variable, the message is encrypted. The receiver reads the value into
their `rs` variable (decrypting with `ok` if non-empty).

 * `dh[es][es]`: A DH calculation is performed between the sender's static or
ephemeral key (the first value) and the receiver's static or ephemeral key (the
second value).  The result is input to the PRF chain, and new `k` and `ok`
variables are computed.

 * `ndh[es][es]`: Like previous, except that a 16-byte random nonce is appended
to the message in cleartext, and is prepended to the DH secret prior to
inputing it to the PRF chain.  This is necessary in cases where DH calculations
might be reused.

In addition to the descriptor-specified fields, every Noise message begins with
a "prologue" that can contain arbitrary plaintext for routing, versioning, or
other purposes.

Each Noise message also ends with a payload which contains arbitrary data, and
will be encrypted if the `ok` is non-empty.

2.4. Example Noise protocols
-----------------------------

The following "Box" protocols represent one-shot messages from a sender to a
recipient.

    Box naming:
     S_ = static key for sender known to recipient
     N_ = no static key for sender
     X_ = static key for sender transmitted to recipient
     _S = static key for recipient known to sender 
     _E = static and ephemeral keys for recipient known to sender 

    BoxSS(s, rs):            # ~ Nacl crypto_box
      ndhss  

    BoxNS(rs):               # ~ public-key encryption
      e, dhes

    BoxXS(s, rs):            # ~ miniLock, old Noise box
      e, dhes, s, dhss

    BoxNE(rs, re):           # ~ public-key encryption + prekey
      e, dhee, dhes

    BoxXE(s, rs, re):        # ~ TripleDH
      e, dhee, dhes, s, dhse

The following Noise protocols represent handshakes where the initiator and
responder exchange messages.

    Handshake naming:

     N_ = no static key for initiator
     X_ = static key for initiator transmitted to responder
     _S = static key for responder known to initiator
     _X = static key for responder transmitted to initiator
     _E = static key and an initial prekey for responder are known
          to the initiator (but responder will also use a fresher
          ephemeral)

    HandshakeNX():           # ~ Ntor (+ server-id-hiding)
      -> e
      <- e, dhee, s, dhse

    HandshakeXX(s):          # ~ old Noise pipe
      -> e
      <- e, dhee, s, dhse
      -> s, dhse

    HandshakeNS(rs):         
      -> e, dhes
      <- e, dhee

    HandshakeXS(s, rs):
      -> e, dhes
      <- e, dhee
      -> s, dhse

    HandshakeNE(s, rs, re):
      -> e, dhee, dhes
      <- e, dhee

    HandshakeXE(s, rs, re):
      -> e, dhee, dhes, s, dhse
      <- e, dhee, dhes


3. Data Structures
===================

    struct {
        uint32 msg_len;
        uint32 prologue_len;
        uint8 prologue[prologue_len];

        /* 0 or more of of following (public_key) */ 
        PublicKey public_key;

        Payload payload;
    } NoiseMessage;

    struct {
        uint8 public_key[DH_LEN];   
    } PublicKey;

    struct {
        uint8 data[];
        uint8 padding[padding_len];
        uint32 padding_len;
    } Payload;

The public key and payload structures may be in plaintext, or may be
encrypted-and-authenticated ciphertexts.  The hash value h is included as
additional authenticated data for the payload ciphertext.

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

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al., and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike and Christian Winnerlein assisted in designing the key derivation process. The Noise KDF has some similarity with HKDF from Hugo Krawzcyk, who also provided some feedback.

Additional feedback on spec and pseudocode came from: Jonathan Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier versions.
