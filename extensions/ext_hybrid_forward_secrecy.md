---
title:      'Noise Extension: Hybrid Forward Secrecy'
author:     'Rhys Weatherley (rhys.weatherley@gmail.com)'
revision:   '1draft'
date:       '2016-08-30'
---

1. Motivation
=============

Once quantum computers become available it is possible that existing
Noise DH algorithms such as `25519` and `448` will become vulnerable.
This might allow a future adversary armed with a quantum computer to
read archived communications.

Using currently-known post-quantum cryptography we may be able to
strengthen the secrecy of current communications against future adversaries.

This document describes an extension to the Noise protocol to augment
handshakes with additional forward secrecy.  We describe the general
method here.  Separate extensions will describe specific post-quantum
algorithms.

For demonstration purposes, we assume that `448` is being used to
strengthen a `25519` handshake.  This allows us to describe the minimum
changes necessary to Noise to add extra forward secrecy to a handshake
using existing Noise primitives.  In a practical implementation,
`448` would of course be replaced by a post-quantum algorithm.

2. Protocol naming
==================

The name of the DH function in the protocol name is modified to
include a pair of identifiers separated by a plus sign; for example:

    Noise_XXhfs_25519+448_AESGCM_SHA256

The pattern name `XXhfs` indicates that that pattern `XX` has been
transformed using the "hybrid forward secrecy" transformation, which
is defined later.

The DH function for the first name in the pair (`25519`) plays the same
role as in regular Noise.  The DH function for the second name in the pair
(`448`) specifies the algorithm that will be used to add extra forward
secrecy to an otherwise plain `Noise_XX_25519_AESGCM_SHA256` handshake.

If a protocol name includes an extra forward secrecy function, then the
pattern must include the `"f"` and `"dhff"` tokens described later.
Otherwise the protocol name is invalid.

Conversely, a pattern that includes `"f"` and `"dhff"` tokens can only
be used with a protocol name that includes an extra forward secrecy
function.

3. Crypto functions
===================

To distinguish the regular DH algorithm from that used for extra forward
secrecy, we add the following functions:

 * **`GENERATE_KEYPAIR_F()`**: Generates a new DH key pair for the extra
   forward secrecy algorithm.

 * **`DH_F(key_pair, public_key)`**: Performs a DH calculation for the
   extra forward secrecy algorithm.

 * **`DHLEN_F`** = A constant specifying the size in bytes of public keys
   and `DH_F` outputs for the extra forward secrecy algorithm.

This extension uses these functions to generate and operate with
ephemeral keys only.

4. Changes to HandshakeState
============================

4.1. Variables
--------------

Two extra variables are added to the state:

 * `f`: The local ephemeral forward secrecy key pair.
 * `rf`: The remote party's ephemeral forward secrecy key.

Both of these variables are instances of the second DH function from
the protocol name.  If the protocol name does not include a second
DH function, then the `f` and `rf` variables are not used by the
handshake.

4.2. Initialization
-------------------

`Initialize()` is modified to include `f` and `rf` parameters.  If either
value is supplied as a pre-message then that value must be hashed
during the fourth pre-message step of the handshake.  Pre-messages
are mixed in the order `e`, `f`, `s`, initiator values first.

4.3. Tokens
-----------

Two new tokens are added for use in defining message patterns:
`"f"` and `"dhff"`.  All other tokens continue to operate as before.

Token handling for `WriteMessage()` is modified as follows:

 * For `"f"`:  Sets `e = GENERATE_KEYPAIR_F()`, overwriting any previous
   value for `f`.  Appends `EncryptAndHash(f.public_key)` to the buffer.

 * For `"dhff"`:  Calls `MixKey(DH_F(f, rf))`.

Token handling for `ReadMessage()` is modified as follows:

 * For `"f"`: Sets `temp` to the next `DHLEN_F + 16` bytes of the message if
   `HasKey() == True`, or to the next `DHLEN_F` bytes otherwise.  Sets `rf`
   to `DecryptAndHash(temp)`.  

 * For `"dhff"`:  Calls `MixKey(DH_F(f, rf))`.

Note that the `"f"` token value will be encrypted if a `"dhee"` token
has already been seen in the pattern, or if pre-shared keys are involved.

Given that post-quantum cryptography is very new, it is possible that
weaknesses may be found in whatever algorithm is chosen.  Encryption
of `"f"` tokens can help hide patterns in the post-quantum values
that might allow cryptanalysis.

Encryption of `"f"` tokens may also be useful for implementing an
Elligator-like scheme that converts post-quantum values into something
indistinguishable from random.

4.4. Handling of pre-shared keys
--------------------------------

The standard Noise specification modifies `Initialize()` and the handling
of the `"e"` token to mix the pre-shared key with the handshake state,
using the value of `e.public_key` as a random nonce.

This behavior is retained when hybrid forward secrecy is in use.  Operations
involving `e` are modified but operations involving `f` are not modified.
The `e.public_key` value should be sufficient as a random nonce on its own.

Some post-quantum algorithms may wish to reuse `f` or parts of `f` between
sessions because of the expense of generating the value.  This means that
`f` may not contain enough randomness to be an effective session nonce.

5. Message patterns for hybrid forward secrecy
==============================================

5.1. The `hfs` pattern transformation
-------------------------------------

This extension defines a transformation named `hfs` that modifies an
existing interactive pattern into one involving hybrid forward secrecy.
The transformation rules are:

 * A sequence of tokens `"e, dhee"` in the original pattern is replaced with
   the sequence `"e, dhee, f, dhff"`.
 * A singleton token `"e"` in the original pattern that is not followed by
   `"dhee"` is replaced with the sequence `"e, f"`.
 * If the pattern contains `"e"` in its pre-message, then `"f"` is added
   to the pre-message.
 * If the pattern contains `"re"` in its pre-message, then `"rf"` is added
   to the pre-message.

The following examples demonstrate the transformation:

    Noise_NNhfs():
      -> e, f
      <- e, dhee, f, dhff

    Noise_XXhfs(s, rs):
      -> e, f
      <- e, dhee, f, dhff, s, dhse
      -> s, dhse

    Noise_IKhfs(s, rs):
      <- s
      ...
      -> e, f, dhes, s, dhss
      <- e, dhee, f, dhff, dhes

    Noise_XXfallback+hfs(s, rs, re, rf):
      <- e, f
      ...
      -> e, dhee, f, dhff, s, dhse
      <- s, dhse

When pattern transformations are composed, we use a plus sign as a separator,
mirroring the practice for DH function names.  The transformations should
be listed in the order in which they are applied to a basic pattern.
If the order doesn't matter, then the parties will need to agree on a
canonical ordering for the purpose of choosing a common protocol name.

5.2. Pattern validity
---------------------

The following validity rules apply:

 * If `f` or `rf` appears as a pre-message in a pattern, then the
   corresponding `e` or `re` value must also appear as a pre-message.
 * `"f"` tokens for a party must always appear after the corresponding
   `"e"` token for that party.
 * Only a single `"f"` token can be sent by each party.  Alternatively,
   a pre-message `f` or `rf` value for a party can stand in for the token.
 * `"dhff"` tokens must occur only once in the pattern, after both the
   initiator and the responder have provided `"f"` tokens or pre-messages.
 * `"dhff"` must occur after `"dhee"`.

The following is recommended:

 * Where possible, a `"f"` token should occur after a `"dhxy"` token so
   as to protect the token's value with encryption.

Encryption of `"f"` tokens is not a hard requirement because there may
be scenarios where plaintext `"f"` values from both parties makes sense.
Also, the default `hfs` pattern transformation will usually leave the
first `"f"` token in the clear.

5.3. Other hybrid patterns
--------------------------

Not all patterns that are created with the `hfs` transformation may be
useful or safe.  The `Noise_IKhfs` pattern described earlier does not
protect the initiator's static public key with the extra forward secrecy.
This may make `s` vulnerable to future cryptanalysis.  To address this,
another transformation could be applied to move the critical values
later in the handshake:

    Noise_IKhfs+xyz(s, rs):
      <- s
      ...
      -> e, f, dhes
      <- e, dhee, f, dhff
      -> s, dhss
      <- dhes

This does tend to increase the number of turn-arounds.  More experimentation
is required before such a transformation can be standardized.  This extension
provides the basic tools that could be used to define such a transformation
later.

Other transformations are also possible for hybrid forward secrecy.
The New Hope algorithm allows for Alice to generate a public "a" value
that persists between sessions for a limited time.  This saves the expense
of regenerating "a" for each session.  It thus naturally makes sense for
Alice to be the server/responder rather than the client/initiator:

    Noise_XXreversehfs(s, rs):
      -> e
      <- e, dhee, f, s, dhse
      -> f, dhff, s, dhse

As before, other tokens may need to be moved to be covered by the
extra forward secrecy so as to create a useful pattern.

6. Discussion
=============

This extension is solely concerned with augmenting the forward
secrecy of an existing handshake.  It is possible to imagine a further
extension whereby the extra DH function also operates on static keys.

Some post-quantum algorithms like New Hope only support ephemeral
keys, whereas others like SIDHp751 support both ephemeral and
static keys.  Static keys could be handled in one of two ways:

 * Use `25519` or `448` for extra forward secrecy, and the post-quantum
   algorithm for static keys; e.g. `Noise_XXhfs_SIDHp751+448`.
 * Extend the facilities here with new tokens to allow static keys for
   both algorithms; e.g. `Noise_XXhfs+hstatic_448+SIDHp751`.

At the moment we do not make any comment as to the wisdom in doing so
or the mechanisms that would be involved.
