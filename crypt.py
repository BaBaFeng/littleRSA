#!/usr/bin/env python
# -*- coding: utf8 -*-

# author: xiaofengfeng
# create: 2016-12-06 16:58:52

import xutils


def encrypt(message, pub_key):
    keylength = xutils.num_byte(pub_key.n)
    padded = xutils._pad_for_encryption(message, keylength)

    payload = xutils.bytes2int(padded)
    encrypted = xutils.encrypt_int(payload, pub_key.e, pub_key.n)
    block = xutils.int2bytes(encrypted, keylength)
    return block


def decrypt(crypto, priv_key):
    blocksize = xutils.num_byte(priv_key.n)
    encrypted = xutils.bytes2int(crypto)
    decrypted = priv_key.blinded_decrypt(encrypted)
    cleartext = xutils.int2bytes(decrypted, blocksize)

    if cleartext[0:2] != b'\x00\x02':
        raise DecryptionError('Decryption failed')

    try:
        sep_idx = cleartext.index(b'\x00', 2)
    except ValueError:
        raise DecryptionError('Decryption failed')
    print(cleartext)
    return cleartext[sep_idx + 1:]
