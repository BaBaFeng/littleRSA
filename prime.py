#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Create Time: 2016/11/30 16:19:33
# Create author: XiaoFengfeng

"""
生成质数，判断质数
"""
from xrandom import get_randint
from xrandom import get_bits_randint
from xrandom import get_bits_odd_randint

from miller_rabin_primality_testing import miller_rabin_primality_testing


def isprime(num):
    """
    判断一个数是否是质数
    >>> isprime(97)
    True
    >>> isprime(100)
    False
    """
    if num < 10:
        return num in [2, 3, 5, 7]

    if not (1 & num):
        return False
    return miller_rabin_primality_testing(num, 7)


def getprime(xbits):
    """
    生成一个质数
    >>> getprime(64)
    13505411656529702771
    >>> getprime(64)
    11419939612564061833
    """
    assert xbits > 3

    while True:
        integer = get_bits_odd_randint(xbits)
        if isprime(integer):
            return integer
