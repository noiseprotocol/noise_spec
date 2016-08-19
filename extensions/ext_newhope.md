---
title:      'Noise Extension: New Hope'
author:     'Rhys Weatherley (rhys.weatherley@gmail.com)'
revision:   '1draft'
date:       '2016-08-20'
---

1. Introduction
===============

This document describes the post-quantum key exchange algorithm New Hope
and provides information for using it with the Noise protocol.

New Hope [1] is a Diffie-Hellman like key exchange mechanism based on the
Ring Learning with Errors (Ring-LWE) problem.  It is believed to be
secure against an adversary with a quantum computer.  It provides the
equivalent of 128 bits of security.

New Hope supports ephemeral key exchange only, which means that it can
only be used with the `NN` handshake pattern of the standard Noise
protocol.  Alternatively, it can be used as an additional forward
secrecy algorithm with the separate forward secrecy extension to Noise.

When used for additional forward secrecy, New Hope can be applied to
any handshake pattern involving a traditional DH function such as
`25519` or `448`.  For example, `Noise_XX_25519+NewHope_AESGCM_SHA256`.
The traditional function is used for forward secrecy and authentication
and New Hope then enhances the forward secrecy.

New Hope is unusual in that its key sizes and operations vary based on
the party:

 * Alice generates a 1824-byte public key and a 2048-byte private key.
   Her 1824-byte public key is sent to Bob.
 * Bob uses Alice's public key to generate his own 2048-byte public key
   and a 32-byte shared secret.  His 2048-byte public key is sent to Alice.
 * Alice uses her 2048-byte private key and Bob's 2048-byte public key
   to generate her copy of the 32-byte shared secret.

Because of this unusual algorithm shape, modifications are necessary
to the API for DH functions in Noise.  These modifications are described
below.

The reference implementation of New Hope has two variants, which it
refers to as "ref" and "torref".  They differ in the generation of
the public "a" value of the algorithm.  The "ref" variant does not
use a constant-time algorithm to generate "a" which may create issues
in identity-hiding networks such as Tor.  The "torref" variant uses a
constant-time algorithm to generate "a" (and all other values).

This document standardizes the "torref" variant under the Noise DH
function name `NewHope`.  The "ref" variant is not used.

2. Modifications to Noise DH functions
======================================

The standard Noise DH functions have three API elements:

 * **`GENERATE_KEYPAIR()`**: Generates a new DH key pair consisting of
   `public_key` and `private_key` elements.  The `public_key` is assumed
   to be `DHLEN` bytes in length.

 * **`DH(key_pair, public_key)`**: Performs a DH calculation between the
   private key in `key_pair` and `public_key` and returns an output sequence of
   bytes of length `DHLEN`.

 * **`DHLEN`** = A constant specifying the size in bytes of public keys and DH
   outputs.

This API is insufficient for New Hope where the private keys, public keys,
and shared outputs are all of different lengths, and are different for
Alice and Bob.  This extension modifies the API for DH functions as
follows:

 * **`GENERATE_DEPENDENT_KEYPAIR(r)`**:
  * If `r` is empty, then generate a New Hope key pair for Alice,
   consisting of a `private_key` of 2048 bytes in length and a
   `public_key` of 1824 bytes in length.
  * If `r` contains a public key, then generate a New Hope key pair for
    Bob from the parameters in `r`, consisting of a `public_key` of
    2048 bytes in length, and a `shared_output` of 32 bytes in length.
    The `shared_output` must be kept secret.

 * **`DH(key_pair, public_key)`**:
  * If `key_pair` was generated for Alice, then derive and return the
    shared output for Alice from `key_pair.private_key` and Bob's `public_key`.
  * If `key_pair` was generated for Bob, then return `key_pair.shared_output`
    and ignore `public_key`.

 * **`DHLEN`** = 32, corresponding to the length of the shared outputs.

 * **`k.PUBLIC_DHLEN` is either 1824 or 2048 depending upon whether `k`
   is playing the Alice or Bob role in the handshake.

3. Modifications to HandshakeState
==================================

New Hope can only be used for ephemeral or additional forward secrecy keys
in a handshake.  If a handshake pattern attempts to use New Hope for
static keys, an error must be reported by `Initialize()`.

When a handshake is initialized, the local ephemeral key pair object and the
remote ephemeral public key object are labelled as either "Alice" or "Bob"
depending upon the handshake pattern.  Regular patterns label the
initiator's ephemeral key as "Alice" and the responder's ephemeral key
as "Bob".  Fallback patterns reverse this labelling.  Labelling a key
will adjust its `PUBLIC_DHLEN` value as appropriate.

All handshake tokens have the same behaviour as before except for `e`.
In `WriteMesssage()` the `e` token is modified as follows:

  * For `"e"`:  Sets `e = GENERATE_DEPENDENT_KEYPAIR(re)`, overwriting any
    previous value for `e`.  Appends `e.public_key` to the buffer.  Calls
    `MixHash(e.public_key)`.

In `ReadMessage()` the `e` token is modified as follows:

  * For `"e"`: Sets `re` to the next `re.PUBLIC_DHLEN` bytes from the message,
    overwriting any previous value for `re`. Calls `MixHash(re.public_key)`. 

If the handshake pattern involves a pre-shared symmetric key (PSK), then
the `"e"` tokens also include a call to `MixKey(e.public_key)` as the
final step.  This is the same as for standard Noise.  Note however that
the public key may have different sizes for Alice and Bob.

If New Hope is being used for additional forward secrecy, then the
modifications are applied to the operations on `f` and `rf` rather
than the operations on `e` and `re`.

4. Registered DH algorithm names
================================

4.1. Generating dependent keys for existing DH algorithms
---------------------------------------------------------

For `25519` and `448`, `GENERATE_DEPENDENT_KEYPAIR(r)` is defined to be
the same as `GENERATE_KEYPAIR()` with the `r` parameter ignored.

4.2. The `NewHope` DH function
------------------------------

 * **`GENERATE_DEPENDENT_KEYPAIR(r)`**: Returns the result of
   `newhope_keygen()` if the key is Alice, or `newhope_sharedb()` if
   the key is Bob.

 * **`DH(key_pair, public_key)`**: Returns the result of `newhope_shareda()`
   if the `key_pair` is Alice, or the previous shared value generated by
   `newhope_sharedb()` if the `key_pair` is Bob.

 * **`DHLEN`** = 32

 * **`PUBLIC_DHLEN`** = 1824 if the key is Alice or 2048 if the key is Bob.

This algorithm must be compatible with the "torref" version of the reference
code from the New Hope authors.

5. Test vector definition
=========================

The Noise test vector format assumes that fixed ephemeral keys can be
set using only their private key.  However, the New Hope API does not
expose a private key in the same sense as `25519` and `448`.

The reference implementation of New Hope acquires 64 bytes of random
seed data from the system to generate the key pair for Alice and the
public "a" value.  The reference implementation acquires 32 bytes of
random seed data from the system to generate the key pair for Bob
relative to "a".

The 64 or 32 bytes of random seed data can be used as the "private key"
component for ephemeral keys in test vectors.

6. References
=============

[1] Erdem Alkim, Léo Ducas, Thomas Pöppelmann, and Peter Schwabe:
[Post-quantum key exchange – a new hope](https://cryptojedi.org/papers/#newhope).
Proceedings of the 25th USENIX Security Symposium.
