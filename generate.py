#!/usr/bin/env python
# -*- coding: utf8 -*-

# author: xiaofengfeng
# create: 2016-12-06 13:28:43

import xutils
import xrandom
from prime import getprime
from xrandom import get_randint

PRIME_LIST = [65537, 6197, 617, 67]


def get_p_q(nbits):
    all_nbits = nbits * 2

    shift = nbits // 4
    pbits = nbits - shift
    qbits = nbits + shift

    p = getprime(pbits)
    q = getprime(qbits)

    while (p != q) and (xutils.num_bit(p * q) == nbits):
        p = getprime(pbits)
        q = getprime(qbits)

    return p, q


def get_exponent(p, q):
    T = (p - 1) * (q - 1)
    e = 0
    for pri in PRIME_LIST:
        if pri < T and T % pri != 0:
            e = pri
            break
    else:
        raise Exception("e not found.")

    div, d, _ = extended_gcd(e, T)
    return e, d


def extended_gcd(a, b):
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a
    ob = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
    if lx < 0:
        lx += ob
    if ly < 0:
        ly += oa
    return a, lx, ly


def key(nbits):
    while True:
        p, q = get_p_q(nbits // 2)
        try:
            e, d = get_exponent(p, q)
            break
        except Exception as err:
            pass
    n = p * q
    return PublicKey(e, n), PrivateKey(p, q, e, d, n)


class AbstractKey(object):
    __slots__ = ('n', 'e')

    def __init__(self, n, e):
        self.n = n
        self.e = e

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a PEM-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a DER-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    def _save_pkcs1_pem(self):
        """Saves the key in PKCS#1 PEM format, implement in a subclass.

        :returns: the PEM-encoded key.
        :rtype: bytes
        """

    def _save_pkcs1_der(self):
        """Saves the key in PKCS#1 DER format, implement in a subclass.

        :returns: the DER-encoded key.
        :rtype: bytes
        """

    @classmethod
    def load_pkcs1(cls, keyfile, format='PEM'):
        """Loads a key in PKCS#1 DER or PEM format.

        :param keyfile: contents of a DER- or PEM-encoded file that contains
            the key.
        :type keyfile: bytes
        :param format: the format of the file to load; 'PEM' or 'DER'
        :type format: str

        :return: the loaded key
        :rtype: AbstractKey
        """

        methods = {
            'PEM': cls._load_pkcs1_pem,
            'DER': cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(file_format, methods):
        """Checks whether the given file format exists in 'methods'.
        """

        try:
            return methods[file_format]
        except KeyError:
            formats = ', '.join(sorted(methods.keys()))
            raise ValueError('Unsupported format: %r, try one of %s' % (file_format,
                                                                        formats))

    def save_pkcs1(self, format='PEM'):
        """Saves the key in PKCS#1 DER or PEM format.

        :param format: the format to save; 'PEM' or 'DER'
        :type format: str
        :returns: the DER- or PEM-encoded key.
        :rtype: bytes
        """

        methods = {
            'PEM': self._save_pkcs1_pem,
            'DER': self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message, r):
        """Performs blinding on the message using random number 'r'.

        :param message: the message, as integer, to blind.
        :type message: int
        :param r: the random number to blind with.
        :type r: int
        :return: the blinded message.
        :rtype: int

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """

        return (message * pow(r, self.e, self.n)) % self.n

    def unblind(self, blinded, r):
        """Performs blinding on the message using random number 'r'.

        :param blinded: the blinded message, as integer, to unblind.
        :param r: the random number to unblind with.
        :return: the original message.

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        div, d, _ = extended_gcd(r, self.n)
        return (d * blinded) % self.n


class PrivateKey(AbstractKey):
    def __init__(self, p, q, e, d, n):
        self.p = p
        self.q = q
        self.e = e
        self.d = d
        self.n = n

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PrivateKey(%(p)i, %(q)i, %(e)i, %(d)i, %(n)i)' % self

    def blinded_decrypt(self, encrypted):
        blind_r = xrandom.get_randint(self.n - 1)
        blinded = self.blind(encrypted, blind_r)  # blind before decrypting
        decrypted = xutils.decrypt_int(blinded, self.d, self.n)

        return self.unblind(decrypted, blind_r)

    def blinded_encrypt(self, message):
        blind_r = xrandom.get_randint(self.n - 1)
        blinded = self.blind(message, blind_r)  # blind before encrypting
        encrypted = xutils.encrypt_int(blinded, self.d, self.n)
        return self.unblind(encrypted, blind_r)


class PublicKey(AbstractKey):
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PublicKey(%(e)i, %(n)i)' % self


if __name__ == '__main__':
    pu, pr = key(512)
    from crypt import encrypt
    from crypt import decrypt
    c = encrypt(b"xxxxxxxxjkfasdhj", pu)
    print(decrypt(c, pr))
