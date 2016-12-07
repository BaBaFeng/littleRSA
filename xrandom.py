#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Create Time: 2016/12/05 21:36:47
# Create author: XiaoFengfeng


import os
import binascii
from struct import pack
from xutils import num_bit


def get_bits_randint(nbits):
    """
    获得一个随机的nbits位的自然数
    >>> get_randint(64)
    11911190890459235487
    还有一种办法是：integer = random.randint(pow(2, nbits - 1), pow(2, nbits) - 1)
    但是这种方法生成自然数的执行速度不是很理想,当nbits=10240000时,比我们用的这种方法慢近十倍
    """
    # ord(os.urandom(1)) <= 255 (2**8 - 1)
    quotient, remainder = divmod(nbits, 8)
    ranbytes = os.urandom(quotient)
    if remainder > 0:
        _randint = ord(os.urandom(1))
        _randint >>= (8 - remainder)
        ranbytes = pack("B", _randint) + ranbytes
    integer = int(binascii.hexlify(ranbytes), 16)

    # num_bits(1 << n - 1) = n
    integer |= 1 << (nbits - 1)
    return integer


def get_bits_odd_randint(nbits):
    """
    获得一个随机的nbits位的奇数
    >>> get_odd_randint(64)
    17505015390430285231
    """
    integer = get_bits_randint(nbits)
    return 1 | integer


def get_randint(max):
    """
    随机生成一个3到max的自然数
    >>> get_randint(2048)
    1568
    还有一种办法是integer = random.randint(a, b),当b-a越来越大的时候,生成自然数的速度会越来越慢
    """
    nbits = num_bit(max)

    integer = get_bits_randint(nbits)
    while integer > max:
        integer = get_bits_randint(nbits)
        nbits -= 1
    return integer


def get_rand_byte(bits):
    return os.urandom(bits)
