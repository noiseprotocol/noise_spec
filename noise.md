
# Introduction

Noise is a pair of crypto protocols:

 * Noise boxes protect stand-alone messages (similar to PGP, NaCl, etc.)
 * Noise pipes protect interactive sessions (similar to SSL, SSH, CurveCP, etc.)

Noise pipes are built from Noise boxes for easy implementation.

Noise offers a simple and efficient cryptographic core which can be used in different applications.

# Notation

# Data Structures

## Ciphersuite variables

    DH_LEN = ?? # Length in bytes of DH private, public keys, and DH outputs
    MAC_LEN = ?? # Length in bytes that ciphertext is enlarged due to MAC

## Basic structures: blobs, boxes, and extension data

    struct {
        bytes encrypted_contents[contents_len];
        bytes encrypted_padding[padding_len];
        bytes encrypted_padding_len[4];
        bytes mac[MAC_LEN];
    } NoiseBlob;

    struct {
        NoiseBlob header;  # sender public key
        NoiseBlob body;     # contents
    } NoiseBox;

    struct {
        uint32 len;
        bytes data[len];
    } ExtensionData;

## Standalone boxes

    struct {
        uint32 len;
        ExtensionData ext_data;
        bytes sender_eph_key_pub[DH_LEN];
        NoiseBox box;
    } StandaloneBox;

## Boxes and messages for pipes

    struct {
        uint32 len;
        ExtensionData start_ext_data;
        bytes client_eph_key_pub[DH_LEN];
    } StartMessage;

    struct {
        uint32 len;
        ExtensionData server_ext_data;
        bytes server_eph_key_pub[DH_LEN];
        NoiseBox box;
    } ServerBox;

    struct {
        uint32 len;
        ExtensionData client_ext_data;
        NoiseBox box;
    } ClientBox;

    struct {
        uint32 len;
        NoiseBlob blob;
    } BlobMessage;

# Functions

# Ciphersuite variables

    SUITE_NAME = ? # 24-byte string uniquely naming the ciphersuite
    CC_LEN = ? # Length in bytes of cipher context

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

# Key Derivation

All Noise ciphersuites use the following HMAC-SHA2-512 based key derivation function:

    CV_LEN = 48
    H_LEN = 64  # output length of hash, >= 32

    KDF(secret, extra_secret, info, output_len):
        # Outputs a byte sequence that the caller typically splits into multiple variables
        # such as a chain variable and cipher context, or two cipher contexts.
        #
        # The 'extra_secret' is used to pass a chaining variable to mix into the KDF.
        # The 'info' ensures that applying the KDF to the same secret values will 
        # produce independent output, provided 'info' is different.

        output = []
        t = zeros[H_LEN]
        for c = 0...(ceil(output_len / H_LEN) - 1)
            t = HMAC-SHA2-512(secret, info || (byte)c || t[0:32] || extra_secret)
            output = output || t
        return output

# Box and blob creation

    noiseBlob(cc, pad_len, contents, authtext):
        plaintext = contents || random(pad_len) || (uint32)pad_len
        return ENCRYPT(cc, plaintext, authtext)

    noiseBox(eph_key, sender_key, target_key_pub, pad_lens[2], contents, authtext, kdf_num, cv):
        dh1 = DH(eph_key.priv, target_key_pub)
        dh2 = DH(sender_key.priv, target_key_pub)
        cc1 || cv1 = KDF(dh1, cv,  SUITE_NAME || (byte)kdf_num, CC_LEN + CV_LEN)
        cc2 || cv2 = KDF(dh2, cv1, SUITE_NAME || (byte)(kdf_num + 1), CC_LEN + CV_LEN)
        header = noiseBlob(cc1, pad_len[0], sender_key.pub, authtext)
        body = noiseBlob(cc2, pad_len[1], contents, authtext || header)
        return (header || body), cv2

## Creating standalone boxes

    standaloneBox(ext_data, sender_key, recvr_key_pub, pad_lens, contents):
        sender_eph_key = GENERATE_KEY()
        authtext = ext_data || sender_eph_key.pub || recvr_key_pub
        box = noiseBox(sender_eph_key, sender_key, recvr_key_pub, pad_lens,
                                  contents, authtext, 0, zeros[CV_LEN])
        return addLen(ext_data || sender_eph_key.pub || box), sender_eph_key

# Creating boxes and messages for pipes

    startMessage(start_ext_data):
        client_eph_key = GENERATE_KEY()
        return addLen(start_ext_data || client_eph_key.pub), client_eph_key

    serverBox(start_ext_data, server_ext_data,
                    server_key, client_eph_key_pub, pad_lens, contents):
        server_eph_key = GENERATE_KEY()
        authtext = start_ext_data || server_ext_data || server_eph_key.pub || client_eph_key_pub
        box, cv_h1 = noise_box(server_eph_key, server_key, client_eph_key_pub,
                                                pad_lens, contents, authtext, 2, zeros[CV_LEN])
        return addLen(server_ext_data || box), server_eph_key, cv_h1

    clientBox(start_ext_data, server_ext_data, client_ext_data,
                    client_eph_key, client_key, server_eph_key_pub, pad_lens, contents):
        authtext = start_ext_data || server_ext_data || client_ext_data || client_eph_key.pub ||
                          server_eph_key_pub
        box, cv_h2 = (client_eph_key, client_key, server_eph_key_pub,
                                pad_lens, contents, authtext, 4, cv_h1)
        return addLen(client_ext_data ||  box), cv_h2

    blobMessage(cc, pad_len, contents):
        blob = noise_blob(cc, pad_len, contents)
        return len(blob) || blob

# Pipe Handshake

(C,c)   : client's public key C and private key c
(S,s)   : server's public key S and private key s
(C',c') : client's ephemeral public key C' and private key c'
(S',s') : server's ephemeral public key S' and private key s'

    Client: start_msg, client_eph_key = startMessage("")
    Client->Server: start_msg

    Server: server_box, server_eph_key, cv_h1 =
        serverBox("", "", server_key, start_msg.client_eph_key_pub,
                         server_pad_lens, server_handshake_data)
    Server->Client: server_box

    Client: client_box, cv_h2 =
        clientBox("", "", "", client_eph_key, client_key, server_box.server_eph_key_pub,
                        client_pad_lens, client_handshake_data)
    Client->Server: client_box

    Both: cc_client || cc_server = KDF(cv_h2, zeros[CV_LEN], SUITE_NAME || (byte)6, CC_LEN*2)

    # In any order:

    Client: blob_message = blobMessage(cc_client, pad_len, app_data)
    Client->Server: blob_message

    Server: blob_message = blobMessage(cc_server, pad_len, app_data)
    Server->Client: blob_message

# IPR

The Noise specification (this document) is hereby placed in the public domain.

# Acknowledgements

Noise is inspired by the NaCl and CurveCP protocols from Dan Bernstein et al., and also by HOMQV from Hugo Krawzcyk.

Moxie Marlinspike and Christian Winnerlein assisted in designing the key derivation process. The Noise KDF has some similarity with HKDF from Hugo Krawzcyk, who also provided some feedback.

Additional feedback on spec and pseudocode came from: Jonathan Rudenberg, Stephen Touset, and Tony Arcieri.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier versions.
