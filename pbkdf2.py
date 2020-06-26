#!/usr/bin/python
# SPDX-License-Identifier: MIT
# Copyright (c) 2014 Michael Ortmann

import binascii
import hashlib
import hmac
import struct
import sys

print('start')

# rfc 2898

def f(digestmod, hlen, p, s, c, i):
    prf = hmac.new(p, None, digestmod)
    prf2 = prf.copy()
    prf2.update(s + struct.pack('>i', i)) # faster than ''.join([chr(i >> j & 0xff) for j in (24, 16, 8, 0)])
    u1 = prf2.digest()
    u2 = bytearray(u1)

    for i in range(2, c + 1):
        prf2 = prf.copy()
        prf2.update(u1)
        u1 = prf2.digest()
        u3 = bytearray(prf2.digest())
        u2 = [u2[i] ^ u3[i] for i in range(hlen)]

    return ''.join([chr(c2) for c2 in u2])

def pbkdf2_hmac(digestmod, p, s, c, dklen=None):
    hlen = digestmod().digest_size

    if not dklen:
        dklen = hlen
    elif dklen > (2 ** 32 - 1) * hlen:
        raise Exception('key too long')

    l = -(-dklen // hlen) # faster than math.ceil(dklen / hlen)
    r = dklen - (l - 1) * hlen
    dk = ''.join([f(digestmod, hlen, p, s, c, i) for i in range(1, l + 1)])[:dklen]

    if sys.version_info[0] >= 3:
        return binascii.b2a_hex(dk.encode('iso-8859-1'))
    else:
        return dk.encode('hex')

# rfc6070

def test_pbkdf2():
    if (pbkdf2_hmac(hashlib.sha1, b'password', b'salt', 1, 20) == b'0c60c80f961f0e71f3a9b524af6012062fe037a6') and \
       (pbkdf2_hmac(hashlib.sha1, b'password', b'salt', 2, 20) == b'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957') and \
       (pbkdf2_hmac(hashlib.sha1, b'password', b'salt', 4096, 20) == b'4b007901b765489abead49d926f721d065a429c1') and \
       (pbkdf2_hmac(hashlib.sha1, b'password', b'salt', 16777216, 20) == b'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984') and \
       (pbkdf2_hmac(hashlib.sha1, b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25) == b'3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'):
        print("test_pbkdf2(): OK")
    else:
        print("test_pbkdf2(): ERROR")

print('test_pbkdf2() will take some time, 1m5s with AMD Ryzen 7 3700X and Python 3.8.3')
test_pbkdf2()

print('end')
