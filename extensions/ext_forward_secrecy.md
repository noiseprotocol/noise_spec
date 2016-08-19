---
title:      'Noise Extension: Additional Forward Secrecy'
author:     'Rhys Weatherley (rhys.weatherley@gmail.com)'
revision:   '1draft'
date:       '2016-08-20'
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

    Noise_XX_25519+448_AESGCM_SHA256

The DH function for the first name in the pair (`25519`) plays the same
role as in regular Noise.  The DH function for the second name in the pair
(`448`) specifies the algorithm that will be used to add additional forward
secrecy to an otherwise plain `Noise_XX_25519_AESGCM_SHA256` handshake.

The two DH functions can be thought of as the "authentication function"
and the "forward secrecy function" as the first function will be
involved in authentication operations in the handshake, but the second
function does not provide any additional authentication of the parties.

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

4. Changes to HandshakeState
============================

4.1. Variables
--------------

Two extra variables are added to the state:

 * `f`: The local ephemeral forward secrecy key pair.
 * `rf`: The remote party's ephemeral forward secrecy key.

Both of these variables are instances of the second DH function from
the protocol name.  If the protocol name does not include a second
DH function, then the `f` and `rf` variables are ignored by the handshake.

4.2. Initialization
-------------------

`Initialize()` is modified to include `f` and `rf` parameters.  If either
value is supplied as a pre-message then that value must be hashed
during the fourth pre-message step of the handshake.  Pre-messages
are mixed in the order `e`, `f`, `s`.

If a dependent handshake pattern involves a pre-shared symmetric key,
then `Initialize()` must also call `MixKey()` on the ephemeral forward
secrecy public key after calling `MixHash()` on it.  The order of
`MixHash()` and `MixKey()` calls is: `MixHash(e)`, `MixKey(e)`,
`MixHash(f)`, `MixKey(f)`.

Any handshake pattern whose pre-message includes `"e"` implies that
both `e` and `f` (or `re` and `rf`) parameter values must be supplied.
For example, `Noise_XXfallback_25519+448_AESGCM_SHA256` requires
that both the ephemeral and forward ephemeral values must be copied from
the previous `Noise_IK_25519+448_AESGCM_SHA256` handshake in Noise Pipes.

4.3. Tokens
-----------

Modifications are required to the `"e"` and `"dhee"` tokens, but all other
tokens continue to operate as before.

Token handling for `WriteMessage()` is modified as follows:

 * For `"e"`:  Sets `e = GENERATE_KEYPAIR()`, overwriting any previous
   value for `e`.  Appends `e.public_key` to the buffer.  Calls
   `MixHash(e.public_key)`.  Then sets `f = GENERATE_KEYPAIR_F()`,
   overwriting any previous value for `f`.  Appends `f.public_key`
   to the buffer.  Calls `MixHash(f.public_key)`.

 * For `"dhee"`:  Calls `MixKey(DH(e, re))` and then `MixKey(DH_F(f, rf))`.

Token handling for `ReadMessage()` is modified as follows:

 * For `"e"`: Sets `re` to the next `DHLEN` bytes from the message,
   overwriting any previous value for `re`. Calls `MixHash(re.public_key)`. 
   Then sets `rf` to the next `DHLEN_F` bytes from the message,
   overwriting any previous value for `rf`. Calls `MixHash(rf.public_key)`. 

 * For `"dhee"`:  Calls `MixKey(DH(e, re))` and then `MixKey(DH_F(f, rf))`.

5. Discussion
=============

It is possible to imagine that `25519+448` might create a virtual DH
function that is transparent to the rest of the Noise implementation.
Public keys would be concatencations of the underlying values and
`DH(x, ry)` operations would transparently concatenate the outputs
into a single input to `MixKey()`.

This alternative was explored but actually led to quite a bit of
implementation complexity.  Consider the `"dhes"` token: the ephemeral
component is a combination of two values but the static component is a
single value.  The implementation needs to decompose the ephemeral
component first before combining it with the static component.

The treatment of `DHLEN` also becomes more complicated with virtual
DH functions as the length of the DH outputs is different for
`"dhee"` and `"dhes"` / `"dhse"` within the same handshake.
It is no longer possible to use a simple constant for `DHLEN`.

With a virtual DH function name of `25519+448` it is tempting to simply
double the static keys as well.  That would simplify the virtual DH
function handling.  However, there are some post-quantum algorithms that
can only perfom ephemeral key exchange (e.g. New Hope) so decomposition
and differing `DHLEN` values still comes into play.

Doubling the static keys also implies that any handshake involving
additional forward secrecy must also supply two sets of static keys
for authentication.  The purpose of this extension is to add extra
forward secrecy only with no change to the set of authentication keys
held by the parties.

Should it make sense in the future to run two authentications in
parallel, it is suggested that the plus sign in the protocol name
be replaced with another symbol.  For example,
`Noise_XX_25519*448_AESGCM_SHA256`.  That will make it clear as
to whether the handshake only involves additional forward secrecy,
or it also involves additional authentication.
