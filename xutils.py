#!/usr/bin/env python
# -*- coding: utf8 -*-

# author: xiaofengfeng
# create: 2016-12-06 14:02:20

import os
import binascii
from struct import pack

import sys
from struct import pack

MAX_INT = sys.maxsize
MAX_INT64 = (1 << 63) - 1
MAX_INT32 = (1 << 31) - 1
MAX_INT16 = (1 << 15) - 1

# Determine the word size of the processor.
if MAX_INT == MAX_INT64:
    # 64-bit processor.
    MACHINE_WORD_SIZE = 64
elif MAX_INT == MAX_INT32:
    # 32-bit processor.
    MACHINE_WORD_SIZE = 32
else:
    # Else we just assume 64-bit processor keeping up with modern times.
    MACHINE_WORD_SIZE = 64

# Range generator.
try:
    # < Python3
    range = xrange
except NameError:
    # Python3
    range = range

# ``long`` is no more. Do type detection using this instead.
try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)


def num_bit(num):
    return len(bin(num)) - 2


def num_byte(num):
    quanta, mod = divmod(num_bit(num), 8)
    if mod or num == 0:
        quanta += 1
    return quanta


def bytes2int(byte):
    return int(binascii.hexlify(byte), 16)


def encrypt_int(message, ekey, n):
    if message < 0:
        raise ValueError('Only non-negative numbers are supported')

    if message > n:
        raise OverflowError("The message %i is too long for n=%i" % (message, n))

    return pow(message, ekey, n)


def decrypt_int(cyphertext, dkey, n):
    message = pow(cyphertext, dkey, n)
    return message


def bytes_leading(raw_bytes, needle=b'\x00'):
    leading = 0
    _byte = needle[0]
    for x in raw_bytes:
        if x == _byte:
            leading += 1
        else:
            break
    return leading


def int2bytes(number, fill_size=None, chunk_size=None, overflow=False):
    if number < 0:
        raise ValueError("Number must be an unsigned integer: %d" % number)

    if fill_size and chunk_size:
        raise ValueError("You can either fill or pad chunks, but not both")

    number & 1

    raw_bytes = b''

    num = number
    word_bits, _, max_uint, pack_type = get_word_alignment(num)
    pack_format = ">%s" % pack_type
    while num > 0:
        raw_bytes = pack(pack_format, num & max_uint) + raw_bytes
        num >>= word_bits
    # Obtain the index of the first non-zero byte.
    zero_leading = bytes_leading(raw_bytes)
    if number == 0:
        raw_bytes = b'\x00'
    raw_bytes = raw_bytes[zero_leading:]

    length = len(raw_bytes)
    if fill_size and fill_size > 0:
        if not overflow and length > fill_size:
            raise OverflowError("Need %d bytes for number, but fill size is %d" % (length, fill_size))
        raw_bytes = raw_bytes.rjust(fill_size, b'\x00')
    elif chunk_size and chunk_size > 0:
        remainder = length % chunk_size
        if remainder:
            padding_size = chunk_size - remainder
            raw_bytes = raw_bytes.rjust(length + padding_size, b'\x00')
    return raw_bytes


def get_word_alignment(num, force_arch=64, _machine_word_size=MACHINE_WORD_SIZE):
    max_uint64 = 0xffffffffffffffff
    max_uint32 = 0xffffffff
    max_uint16 = 0xffff
    max_uint8 = 0xff

    if force_arch == 64 and _machine_word_size >= 64 and num > max_uint32:
        # 64-bit unsigned integer.
        return 64, 8, max_uint64, "Q"
    elif num > max_uint16:
        # 32-bit unsigned integer
        return 32, 4, max_uint32, "L"
    elif num > max_uint8:
        # 16-bit unsigned integer.
        return 16, 2, max_uint16, "H"
    else:
        # 8-bit unsigned integer.
        return 8, 1, max_uint8, "B"


def _pad_for_encryption(message, target_length):
    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only' ' space for %i' % (msglength, max_msglength))

    padding = b''
    padding_length = target_length - msglength - 3

    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b''.join([b'\x00\x02', padding, b'\x00', message])
