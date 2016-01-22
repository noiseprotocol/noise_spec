
Noise v0 (draft) 
=================

 * **Author:** Trevor Perrin (noise @ trevp.net)
 * **Date:** 2015-11-19
 * **Revision:** 19 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
================

Noise is a framework for crypto protocols based on Diffie-Hellman key agreement.
Noise can describe protocols that consist of a single message as well as
interactive protocols.

2. Overview
============

2.1. Terminology
-----------------

A Noise protocol begins with two parties exchanging **handshake messages**.
During this **handshake phase** the parties exchange DH public keys and perform
a sequence of DH operations, hashing the DH results into a shared secret key.
After the handshake phase each party can use this shared key to send encrypted
**transport messages** .

The Noise framework supports handshakes where each party has a
long-term **static key pair** and/or an **ephemeral key pair**.  The handshake
is described by **patterns**.  A **message pattern** is a sequence of
**tokens** that specifies the DH public keys that comprise a handshake message,
and the DH operations that are performed when sending or receiving that
message.  A **handshake pattern** specifies the sequence of message patterns
that comprise a handshake.

A handshake pattern can be instantiated by **DH functions**, **cipher
functions**, and a **hash function** to give a concrete protocol.  An
application using Noise must handle some **application responsibilities** on its
own, such as indicating message lengths.

2.2. Handshake state machine
-----------------------------

The core of Noise is a set of variables maintained by each party during a
handshake, and rules for sending and receiving handshake messages by
sequentially processing the tokens from a message pattern.

Each party to a handshake maintains the following variables:

 * **`s, e`**: The local party's static and ephemeral key pairs (which may be empty).

 * **`rs, re`**: The remote party's static and ephemeral public keys (which may be empty).

 * **`h`**: A value that hashes all the handshake data that's been sent and received.

 * **`ck`**: A "chaining key" that hashes all previous DH outputs.  Once the
   handshake completes, the chaining key will be used to derive the encryption
   keys for transport messages.
 
 * **`k, n`**: A encryption key `k` (which may be empty) and a counter-based
   nonce `n`.  Whenever a new DH output causes a new `ck` to be calculated, a
   new `k` is also calculated from the same inputs.  The key `k` and nonce `n`
   are used to encrypt static public keys and handshake payloads, incrementing
   `n` with each encryption.  Encryption with `k` uses an "AEAD" cipher mode
   and includes the current `h` value as "associated data" which is covered by
   the AEAD authentication tag.  Encryption of static public keys and payloads
   provides some confidentiality during the handshake phase.  It also confirms
   to the other party that the correct key was derived, and that the sender has
   a matching view of transmitted handshake data.

To send a handshake message, the sender sequentially processes each token from
a message pattern.  The possible tokens are:

 * **`"e"`**: The sender generates a new ephemeral key pair and stores it in
   the `e` variable, writes the ephemeral public key as cleartext into the
   message buffer, and hashes the public key along with the old `h` to derive a
   new `h`.

 * **`"s"`**: The sender writes its static public key from the `s` variable
   into the message buffer, encrypting it if `k` is non-empty, and hashes the
   output along with the old `h` to derive a new `h`.

 * **`"dhee", "dhse", "dhes", "dhss"`**: The sender performs a DH between
   its corresponding local key pair (whether `s` or `e` is determined by the
   first letter following `"dh"`) and the remote public key (whether `rs` or `re`
   is determined by the second letter following `"dh"`).  The result is hashed
   along with the old `ck` to derive a new `ck` and `k`, and `n` is set to
   zero.

After processing the final token in a handshake message, the sender then writes
the payload (which may be zero-length) into the message buffer, encrypting it
if `k` is non-empty, and hashing the output along with the old `h` to derive a
new `h`.

As a simple example, an unauthenticated DH handshake is described by the
handshake pattern:

      -> e
      <- e, dhee    

The initiator sends the first message, which is simply an ephemeral public key.
The responder sends back its own ephemeral public key.  Then a DH is performed
and the output is hashed into `ck`, which is the final shared key from the
handshake.  Note that a cleartext payload can be sent in the first handshake
message, and an encrypted payload can be sent in the response handshake message.  

The responder can send its static public key (under encryption) and
authenticate itself via a slightly different pattern:

      -> e
      <- e, dhee, s, dhse

In this case, the final `ck` and `k` values are a hash of both DH results.
Since the `dhse` token indicates a DH between the initiator's ephemeral key and
the responder's static key, successful decryption by the initiator of the
second message's payload serves to authenticate the responder to the initiator.

Note that the second message's payload may contain a zero-length plaintext, but
the payload ciphertext will still contain an authentication tag, since
encryption is with an AEAD mode.  The second message's payload can also be used to
deliver certificates for the responder's static public key.

The initiator can send *its* static public key (under encryption), and
authenticate itself, using a handshake pattern with one additional message:

      -> e
      <- e, dhee, s, dhse
      -> s, dhse

The following sections flesh out the details, and add some complications (such
as pre-shared symmetric keys, and "pre-messages" that represent knowledge of
the other party's public keys before the handshake).  However, the core of
Noise is this simple system of variables, tokens, and processing rules, which
allow concise expression of a range of protocols.

3.  Message format
===================

All Noise messages are less than or equal to 65535 bytes in length.
Restricting message size has several advantages:

 * Simpler testing, since it's easy to test the maximum sizes.

 * Reduces the likelihood of errors in memory handling, or integer overflow. 

 * Enables support for streaming decryption and random-access decryption of
   large data streams.

 * Enables higher-level protocols that encapsulate Noise messages to use an efficient
 standard length field of 16 bits.

All Noise messages can be processed without parsing, since there are no type or
length fields.  Of course, Noise messages might be encapsulated within a
higher-level protocol that contains type and length information.  Noise
messages might also encapsulate payloads that require parsing of some sort, but
the payloads are opaque to Noise.

A Noise **transport message** is simply an AEAD ciphertext that is less than or
equal to 65535 bytes in length, and that consists of some encrypted payload
plus a 16-byte authentication tag.  The details depend on the AEAD cipher
function, e.g. AES256-GCM, or ChaCha-Poly1305, but the 16-byte authentication
tag typically occurs at the end of the ciphertext.

A Noise **handshake message** is also less than 65535 bytes.  It begins with a
sequence of one or more DH public keys, as determined by its message pattern.
Following the public keys will be a payload which can be used to convey
certificates or other handshake data.  Static public keys and payloads will be
in cleartext if they occur in a handshake pattern prior to a DH operation, and
will be an AEAD ciphertext if they occur after a DH operation.  (If Noise is
being used with pre-shared keys, this rule is different: *all* static public
keys and payloads will be encrypted; see Section 6).  Like transport messages,
AEAD ciphertexts will expand each encrypted field by 16 bytes for an
authentication tag.

For an example, consider the handshake pattern:

      -> e
      <- e, dhee, s, dhse
      -> s, dhse

The first message consists of a cleartext public key followed by a cleartext
payload (remember that payloads are implicit in the pattern, but are always
present).  The second message consists of a cleartext public key followed by an
encrypted public key followed by an encrypted payload.  The third message
consists of an encrypted public key followed by an encrypted payload.  

Assuming zero-length payloads and DH public keys of 32 bytes, the message sizes
will be 32 bytes (one public key), then 96 bytes (two public keys and two
authentication tags), then 64 bytes (one public key and two authentication
tags).  If pre-shared keys are used, the first message grows in size to 48
bytes, since the first payload becomes encrypted.


4.  Crypto algorithms
======================

A Noise protocol must be instantiated with a concrete set of **DH functions**,
**cipher functions**, and a **hash function**.  The signature for these
functions is defined below.  Some concrete example functions are defined in
Section 9.

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
   unique for the key `k`.  Returns the ciphertext.  Encryption must be done
   with an "AEAD" encryption mode with the associated data `ad` and returns
   a ciphertext that is the same size as the plaintext plus 16 bytes for an
   authentication tag.

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using a cipher
   key `k` of 32 bytes, an 8-byte unsigned integer nonce `n`, and associated
   data `ad`.  Returns the plaintext, unless authentication fails, in which
   case an error is signaled to the caller.

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
`||` operator indicates concatenation of byte sequences:

 * **`HKDF(chaining_key, input_key_material)`**:  Takes a `chaining_key` byte
   sequence of length `HASHLEN`, and an `input_key_material` byte sequence of
   arbitrary length.  Sets the value `temp_key = HMAC-HASH(chaining_key,
   input_key_material)`.  Sets the value `output1 = HMAC-HASH(temp_key, byte(0x01))`.
   Sets the value `output2 = HMAC-HASH(temp_key, output1 || byte(0x02))`.  These
   three values are all `HASHLEN` bytes in length.  Returns the pair
   (`output1`, `output2`).


5. Processing rules for handshake and transport messages
=========================================================

To precisely define the processing rules we adopt an object-oriented
terminology, and present three "objects" which encapsulate state variables and
provide "methods" which implement processing logic.  These three objects are
presented as a hierarchy: each higher-layer object includes one instance of the
object beneath it.  From lowest-layer to highest, the objects are:

 * A **`CipherState`** object contains `k` and `n` variables, which it uses to
   encrypt and decrypt ciphertexts.  During the handshake phase each party has
   a single `CipherState`, but during the transport phase each party has two
   `CipherState` objects: one for sending, and one for receiving.

 * A **`SymmetricState`** object contains a `CipherState` plus `ck` and `h`
   variables.  It is so-named because it encapsulates all the "symmetric
   crypto" used by Noise.  During the handshake phase each party has a single
   `SymmetricState`, which can be deleted once the handshake is finished.

 * A **`HandshakeState`** object contains a `SymmetricState` plus DH variables
   `(s, e, rs, re)` and some variables representing the handshake pattern.
   During the handshake phase each party has a single `HandshakeState`, which
   can be deleted once the handshake is finished.

To execute a Noise protocol you `Initialize()` a `HandshakeState`.  During
initialization you specify the handshake pattern, any local key pairs, and any
public keys for the remote party you have knowledge of.  You may optionally
specify **prologue** data that both parties will confirm is identical (such as
previously exchanged negotiation messages).

After `Initialize()` you call `WriteMessage()` and `ReadMessage()` on the
`HandshakeState` to process each handshake message.  If a decryption error
occurs the handshake has failed and the `HandshakeState` is deleted without
sending further messages.

Processing the final handshake message returns two `CipherState` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  At that point the `HandshakeState`
may be deleted.  Transport messages are then encrypted and decrypted by calling
`Encrypt()` and `Decrypt()` on the relevant `CipherState` with zero-length
associated data.

The below sections describe these objects in detail.

5.1 The `CipherState` object
-----------------------------

A `CipherState` can encrypt and decrypt data based on its `k` and `n` variables:

 * **`k`**: A cipher key of 32 bytes (which may be empty).

 * **`n`**: An 8-byte (64-bit) unsigned integer nonce.

A `CipherState` responds to the following methods.  The `++` post-increment
operator applied to `n` means "use the current `n` value, then increment it".

 * **`InitializeKey(key)`**:  Sets `k = key`.  Sets `n = 0`.

 * **`HasKey()`**: Returns true if `k` is non-empty, false otherwise.

 * **`Encrypt(ad, plaintext)`**:  If `k` is non-empty returns `ENCRYPT(k, n++,
   ad, plaintext)`.  Otherwise returns `plaintext`.

 * **`Decrypt(ad, ciphertext)`**:  If `k` is non-empty returns `DECRYPT(k, n++,
   ad, ciphertext)`.  Otherwise returns `ciphertext`.  If an authentication
   failure occurs in `DECRYPT()` the error is signaled to the caller.

5.2. The `SymmetricState` object
-----------------------------------------

A `SymmetricState` object contains a `CipherState` plus the following
variables:

 * **`ck`**: A chaining key of `HASHLEN` bytes.
 
 * **`h`**: A hash output of `HASHLEN` bytes.

A `SymmetricState` responds to the following methods:   
 
 * **`InitializeSymmetric(handshake_name)`**:  Takes an arbitrary-length
   `handshake_name` byte sequence (see Section 10).  If `handshake_name` is less
   than or equal to `HASHLEN` bytes in length, sets `h` equal to
   `handshake_name` with zero bytes appended to make `HASHLEN` bytes.
   Otherwise sets `h = HASH(handshake_name)`.  Sets `ck = h`. Calls
   `InitializeKey(empty)`.  

 * **`MixKey(input_key_material)`**:  Sets `ck, temp_k = HKDF(ck,
   input_key_material)`.  If `HASHLEN` is 64, then `temp_k` is truncated to 32
   bytes to match `k`.  Calls `InitializeKey(temp_k)`.
   
 * **`MixHash(data)`**:  Sets `h = HASH(h || data)`.

 * **`EncryptAndHash(plaintext)`**: Sets `ciphertext = Encrypt(h, plaintext)`,
   calls `MixHash(ciphertext)`, and returns `ciphertext`.

 * **`DecryptAndHash(ciphertext)`**: Sets `plaintext = Decrypt(h, ciphertext)`,
   calls `MixHash(ciphertext)`, and returns `plaintext`.  

 * **`Split()`**:  Sets `temp_k1, temp_k2 = HKDF(ck, empty)` where `empty` is a
   zero-length byte sequence.  If `HASHLEN` is 64, then `temp_k1` and `temp_k2`
   are truncated to 32 bytes to match `k`.  Creates two new `CipherState`
   objects `c1` and `c2`.  Calls `c1.InitializeKey(temp_k1)` and
   `c2.InitializeKey(temp_k2)`.  Returns the pair `(c1, c2)`.  The caller will
   use the returned `CipherState` objects to encrypt and decrypt transport messages.
   
5.3. The `HandshakeState` object
---------------------------------

A `HandshakeState` object contains a `SymmetricState` plus the following
variables, any of which may be empty:

 * **`s`**: The local static key pair 

 * **`e`**: The local ephemeral key pair

 * **`rs`**: The remote party's static public key

 * **`re`**: The remote party's ephemeral public key 

A `HandshakeState` also has the following variables:

 * **`message_patterns`**: A sequence of message patterns.  Each message pattern is a
   sequence of tokens from the set `("s", "e", "dhee", "dhes", "dhse", "dhss")`.

 * **`message_index`**: An integer indicating the next pattern to fetch from
 `message_patterns`.

A `HandshakeState` responds to the following methods:

 * **`Initialize(handshake_pattern, initiator, prologue, new_s, new_e, new_rs,
   new_re)`**: Takes a valid handshake pattern (see Section 7), and an
   `initiator` boolean specifying this party's role as either initiator or
   responder.  Takes a `prologue` byte sequence which may be zero-length, or
   which may contain context information that both parties want to confirm is
   identical, such as protocol or version negotiation messages sent previously.
   Takes a set of DH keypairs and public keys for initializing local variables,
   any of which may be empty.
 
   * Derives a `handshake_name` byte sequence by combining the names for the 
   handshake pattern and crypto functions, as specified in Section 10. Calls 
   `InitializeSymmetric(handshake_name)`.

   * Calls `MixHash(prologue)`.

   * Sets the `s`, `e`, `rs`, and `re` variables to the corresponding arguments.
   
   * Calls `MixHash()` once for each public key listed in the pre-messages from
     `handshake_pattern`, with the specified public key as input (see Section 7
     for an explanation of pre-messages).  If both initiator and responder have
     pre-messages, the initiator's public keys are hashed first.

   * Sets `message_patterns` to the message patterns from `handshake_pattern`.

   * Sets `message_index = 0` (i.e. the first message pattern).

 * **`WriteMessage(payload, message_buffer)`**: Takes a `payload` byte sequence
   which may be zero-length, and a `message_buffer` to write the output into.

    * Fetches the next message pattern from `message_patterns[message_index]`,
    increments `message_index`, and sequentially processes each token from the
    message pattern:

      * For `"e"`:  Sets `e = GENERATE_KEYPAIR()`, overwriting any previous value
        for `e`.  Appends `e.public_key` to the buffer.  Calls
        `MixHash(e.public_key)`.

      * For `"s"`:  Appends `EncryptAndHash(s.public_key)` to the buffer.  
      
      * For `"dh`*xy*`"`:  Calls `MixKey(DH(x, ry))`.

    * Appends `EncryptAndHash(payload)` to the buffer.  
    
    * If there are no more message patterns returns two new `CipherState`
      objects by calling `Split()`.

 * **`ReadMessage(message, payload_buffer)`**: Takes a byte sequence containing
   a Noise handshake message, and a `payload_buffer` to write the message's
   plaintext payload into.

    * Fetches the message pattern from `message_patterns[message_index]`,
    increments `message_index`, and sequentially processes each token from the
    message pattern:

      * For `"e"`: Sets `re` to the next `DHLEN` bytes from the message. Calls
        `MixHash(re.public_key)`. 
      
      * For `"s"`: Sets `data` to the next `DHLEN + 16` bytes of the message if
      `HasKey() == True`, or to the next `DHLEN` bytes otherwise.  Sets `rs` to
      `DecryptAndHash(data)`.  
      
      * For `"dh`*xy*`"`:  Calls `MixKey(DH(y, rx))`.  

    * Copies the output from `DecryptAndHash(remaining_message)` into the `payload_buffer`.
  
    * If there are no more message patterns returns two new `CipherState`
      objects by calling `Split()`.

6. Pre-shared keys
===================

Noise provides an optional "pre-shared key" or "PSK" mode to support protocols
where both parties already have a shared secret key.  When using pre-shared
keys, the following changes are made:

 * Handshake names (Section 10) use the prefix `"NoisePSK_"` instead of `"Noise_"`.

 * `Initialize()` takes an additional `psk` argument, which is a sequence of
   bytes.  Immediately after `MixHash(prologue)` it sets `ck, temp = HKDF(ck,
   psk)`, then calls `MixHash(temp)`.  This mixes the pre-shared key into the
   chaining key, and also mixes a one-way function of the pre-shared key into
   the `h` value to ensure that `h` is a function of all handshake inputs.

 * `WriteMessage()` and `ReadMessage()` are modified when processing the `"e"`
   token to call `MixKey(e.public_key)` as the final step.  Because the initial
   messages in a handshake pattern are required to start with `"e"` (Section
   7.1), this ensures `k` is initialized from the pre-shared key.  This also
   uses the ephemeral public key's value as a random nonce to prevent
   re-using the same `k` and `n` for different messages.

7. Handshake patterns 
======================

A **message pattern** is some sequence of tokens from the set `("e", "s", "dhee", "dhes", "dhse",
"dhss")`.  A **handshake pattern** consists of:

 * A pattern for the initiator's **pre-message** that is either:
   * `"s"`
   * `"e"`
   * `"s, e"`
   * empty

 * A pattern for the responder's pre-message that takes the same
   range of values as the initiator's pre-message.

 * A sequence of message patterns for the actual handshake messages

The pre-messages represent an exchange of public keys that was somehow
performed prior to the handshake, so these public keys must be inputs to
`Initialize()` for the recipient of the pre-message.  

The first actual handshake message is sent from the initiator to the responder,
the next is sent by the responder, the next from the initiator, and so on in
alternating fashion. 

The following handshake pattern describes an unauthenticated DH handshake:

    Noise_NN():
      -> e
      <- e, dhee

The handshake pattern name is `Noise_NN`.  This naming convention will be
explained in Section 7.3.  The empty parentheses indicate that neither party is
initialized with any key pairs.  The tokens `"s"` and/or `"e"` inside the
parentheses would indicate that the initiator is initialized with static and/or
ephemeral key pairs.  The tokens `"rs"` and/or `"re"` would indicate the same
thing for the responder.

Pre-messages are shown as patterns prior to the delimiter "...", with a
right-pointing arrow for the initiator's pre-message, and a left-pointing arrow
for the responder's pre-message.  If both parties have a pre-message, the
initiator's is listed first (and hashed first).  During `Initialize()`,
`MixHash()` is called on any pre-message public keys, as described in Section
5.3.

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral.  Note that
this pre-knowledge allows an encrypted payload to be sent in the first message,
although full forward secrecy is only achieved with the second message.

    Noise_NK(rs):
      <- s
      ...
      -> e, dhes 
      <- e, dhee

7.1 Pattern validity 
----------------------

Noise patterns must be **valid** in two senses:

 * Parties can only send static public keys they possess, or perform DH between
 keys they possess.

 * Because Noise uses ephemeral public keys as nonces, parties must send an
   ephemeral public key as the first token of the first message they send.
   Also, parties must not send encrypted data (i.e. static public keys and
   payloads) unless they have performed DH between their current ephemeral and
   all of the other party's key pairs.  

Patterns failing the first check will obviously abort the program.  Patterns
failing the second check could result in subtle but catastrophic security flaws.

7.2. One-way patterns 
----------------------

The following example handshake patterns represent "one-way" handshakes
supporting a one-way stream of data from a sender to a recipient.  These
patterns could be used to encrypt files, database records, or other
non-interactive data streams.

Following a one-way handshake the sender can send a stream of transport
messages, encrypting them using the first `CipherState` returned by `Split()`.
The second `CipherState` from `Split()` is discarded - the recipient must not
send any messages using it.

    Naming convention for one-way patterns:    
      N = no static key for sender
      K = static key for sender known to recipient
      X = static key for sender transmitted to recipient

    Noise_N(rs):
      <- s
      ...
      -> e, dhes

    Noise_K(s, rs):
      -> s
      <- s
      ...
      -> e, dhes, dhss

    Noise_X(s, rs):
      <- s
      ...
      -> e, dhes, s, dhss

Note that `Noise_N` is a conventional DH-based public-key encryption.  The
other patterns add sender authentication, where the sender's public key is
either known to the recipient beforehand (`Noise_K`) or transmitted under
encryption (`Noise_X`).

7.3. Interactive patterns 
--------------------------

The following example handshake patterns represent interactive protocols.

    Naming convention for interactive patterns:

      N_ = no static key for initiator
      K_ = static key for initiator known to responder
      X_ = static key for initiator transmitted to responder
      I_ = static key for initiator immediately transmitted to responder,
           without regard for identity-hiding
  
      _N = no static key for responder
      _K = static key for responder known to initiator
      _X = static key for responder transmitted to initiator


    Noise_NN():                      Noise_KN(s):              
      -> e                             -> s                       
      <- e, dhee                       ...                        
                                       -> e                       
                                       <- e, dhee, dhes           
                                             
    Noise_NK(rs):                    Noise_KK(s, rs):
      <- s                             -> s                       
      ...                              <- s                       
      -> e, dhes                       ...                        
      <- e, dhee                       -> e, dhes, dhss           
                                       <- e, dhee, dhes           
                                              
    Noise_NX(rs):                    Noise_KX(s, rs):          
      -> e                             -> s                       
      <- e, dhee, s, dhse              ...                        
                                       -> e                       
                                       <- e, dhee, dhes, s, dhse  


    Noise_XN(s):                     Noise_IN(s):
      -> e                             -> e, s
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                         
    Noise_XK(s, rs):                 Noise_IK(s, rs):            
      <- s                             <- s                         
      ...                              ...                          
      -> e, dhes                       -> e, dhes, s, dhss          
      <- e, dhee                       <- e, dhee, dhes             
      -> s, dhse                                                     
                                        
    Noise_XX(s, rs):                 Noise_IX(s, rs):
      -> e                             -> e, s
      <- e, dhee, s, dhse              <- e, dhee, dhes, s, dhse                                
      -> s, dhse

    Noise_XXr(s, rs):
      -> e
      <- e
      -> dhee, s, dhse
      <- s, dhse

The `Noise_XX` pattern is the most generically useful, since it supports mutual
authentication and transmission of static public keys.  Even if these features
aren't needed, it's possible to use the `Noise_XX` handshake and ignore the
transmitted static public keys, or send dummy static public keys, thus
supporting multiple use cases with a single handshake pattern.

The `Noise_XX` pattern offers stronger identity-hiding for the initiator than
the responder. Since the responder sends their static public key first, the
responder's identity can be revealed by anonymous active probing.  The
`Noise_XXr` pattern flips this around, offering stronger identity protection
to the responder (this relationship between `Noise_XX` and `Noise_XXr` is
similar to the relationship between Hugo Krawczyk's `SIGMA-I` and `SIGMA-R`).


7.4. More patterns
--------------------

The patterns in the previous sections are representative examples which we are
naming for convenience, but they are not exhaustive.  Other valid patterns
could be constructed, for example:

 * It would be easy to modify `Noise_X` to transmit the sender's static public
   key in cleartext instead of encrypted, just by changing `"e, dhes, s, dhss"`
   to `"e, s, dhes, dhss"`.  Since encrypting more of the handshake is usually
   better, we're not bothering to name that pattern.

 * In some patterns both initiator and responder have a static public key, but
   `"dhss"` is not performed.  This DH operation could be added to provide more 
   resilience in case the ephemerals are generated by a bad RNG.

8. Handshake re-initialization and "Noise Pipes"
===============================================

A protocol may support **handshake re-initialization**.  In this case, the
recipient of a handshake message must also receive some indication whether this
is the next message in the current handshake, or whether to re-initialize the
`HandshakeState` and perform a different handshake (see discussion on "Type
fields" in Section 11).

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

9. DH functions, cipher functions, and hash functions
======================================================

9.1. The 25519 DH functions
----------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve25519 DH function (aka "X25519"
   in some specifications).  If the function detects an invalid public
   key, the output may be set to all zeros or any other value that doesn't leak
   information about the private key.

 * **`DHLEN`** = 32

9.2. The 448 DH functions
--------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 keypair.
 
 * **`DH(privkey, pubkey)`**: Executes the Curve448 DH function (aka "X448" in
   some specifications).  If the function detects an invalid public key,
   the output may be set to all zeros or any other value that doesn't leak
   information about the private key.

 * **`DHLEN`** = 56

9.3. The ChaChaPoly cipher functions
------------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 `AEAD_CHACHA20_POLY1305` from RFC 7539.  The 96-bit nonce is formed by encoding
 32 bits of zeros followed by little-endian encoding of `n`.  (Earlier
 implementations of ChaCha20 used a 64-bit nonce, in which case it's compatible
 to encode `n` directly into the ChaCha20 nonce without the 32-bit zero prefix).

9.4. The AESGCM cipher functions
---------------------------

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
 AES256-GCM from NIST SP800-38-D with 128-bit tags.  The 96-bit nonce is formed
 by encoding 32 bits of zeros followed by big-endian encoding of `n`.

9.5. The SHA256 hash function
------------------------------

 * **`HASH(input)`**: `SHA2-256(input)` 

 * **`HASHLEN`** = 32

 * **`BLOCKLEN`** = 64

9.6. The SHA512 hash function
------------------------------

 * **`HASH(input)`**: `SHA2-512(input)` 
 
 * **`HASHLEN`** = 64

 * **`BLOCKLEN`** = 128

9.7. The BLAKE2s hash function
-------------------------------

 * **`HASH(input)`**: `BLAKE2s(input)` with digest length 32.

 * **`HASHLEN`** = 32

 * **`BLOCKLEN`** = 64

9.8. The BLAKE2b hash function
-------------------------------

 * **`HASH(input)`**: `BLAKE2b(input)` with digest length 64.

 * **`HASHLEN`** = 64

 * **`BLOCKLEN`** = 128

10. Handshake names 
=========================

To produce a **handshake name** for `Initialize()` you concatenate the names
for the handshake pattern, the DH functions, the cipher functions, and the hash
function.  For example: 

 * `Noise_XX_25519_AESGCM_SHA256`

 * `Noise_N_25519_ChaChaPoly_BLAKE2s`

 * `Noise_XXfallback_448_AESGCM_SHA512`

 * `Noise_IK_448_ChaChaPoly_BLAKE2b`

If a pre-shared key is in use, then the prefix `NoisePSK_` is used instead of `Noise_`:

 * `NoisePSK_XX_25519_AESGCM_SHA256`

 * `NoisePSK_N_25519_ChaChaPoly_BLAKE2s` 
 
 * `NoisePSK_XXfallback_448_AESGCM_SHA512`

 * `NoisePSK_IK_448_ChaChaPoly_BLAKE2b`


11. Application responsibilities
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

12. Security considerations
===========================

This section collects various security considerations:

 * **Termination**:  Preventing attackers from truncating a stream of transport
   messages is an application responsibility.  See previous section.

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key `k`
 for encryption would be catastrophic.  Implementations must carefully follow
 the rules for nonces.   

 * **Fresh ephemerals**:  Every party in a Noise protocol should send a new
   ephemeral public key and perform a DH with it prior to sending any encrypted
   data.  Otherwise replay of a handshake message could trigger catastrophic
   key reuse. This is one rationale behind the patterns in Section 7, and the
   validity rules in Section 7.1.  It's also the reason why one-way handshakes
   only allow transport messages from the sender, not the recipient.

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

13. Rationale
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


14. IPR
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
