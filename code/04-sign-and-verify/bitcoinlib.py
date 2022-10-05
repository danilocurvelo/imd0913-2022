#!/usr/bin/python
# from bitcoin.py2specials import *
# from bitcoin.py3specials import *
import binascii
import hashlib
import re
import sys
import os
import base64
import time
import random
import hmac
# from bitcoin.ripemd import *

# Elliptic curve parameters (secp256k1)

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)


def change_curve(p, n, a, b, gx, gy):
    global P, N, A, B, Gx, Gy, G
    P, N, A, B, Gx, Gy = p, n, a, b, gx, gy
    G = (Gx, Gy)


def getG():
    return G

# Extended Euclidean Algorithm


def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n



# JSON access (for pybtctool convenience)


def access(obj, prop):
    if isinstance(obj, dict):
        if prop in obj:
            return obj[prop]
        elif '.' in prop:
            return obj[float(prop)]
        else:
            return obj[int(prop)]
    else:
        return obj[int(prop)]


def multiaccess(obj, prop):
    return [access(o, prop) for o in obj]


def slice(obj, start=0, end=2**200):
    return obj[int(start):int(end)]


def count(obj):
    return len(obj)

_sum = sum


def sum(obj):
    return _sum(obj)


def isinf(p):
    return p[0] == 0 and p[1] == 0


def to_jacobian(p):
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p):
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)


def jacobian_add(p, q):
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)


def from_jacobian(p):
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)


def jacobian_multiply(a, n):
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n//2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n//2)), a)


def fast_multiply(a, n):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def fast_add(a, b):
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))

# Functions for handling pubkey and privkey formats


def get_pubkey_format(pub):
    if is_python2:
        two = '\x02'
        three = '\x03'
        four = '\x04'
    else:
        two = 2
        three = 3
        four = 4

    if isinstance(pub, (tuple, list)): return 'decimal'
    elif len(pub) == 65 and pub[0] == four: return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04': return 'hex'
    elif len(pub) == 33 and pub[0] in [two, three]: return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02', '03']: return 'hex_compressed'
    elif len(pub) == 64: return 'bin_electrum'
    elif len(pub) == 128: return 'hex_electrum'
    else: raise Exception("Pubkey not in recognized format")


def encode_pubkey(pub, formt):
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return b'\x04' + encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'bin_compressed':
        return from_int_to_byte(2+(pub[1] % 2)) + encode(pub[0], 256, 32)
    elif formt == 'hex': return '04' + encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    elif formt == 'hex_compressed':
        return '0'+str(2+(pub[1] % 2)) + encode(pub[0], 16, 64)
    elif formt == 'bin_electrum': return encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'hex_electrum': return encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    else: raise Exception("Invalid format!")


def decode_pubkey(pub, formt=None):
    if not formt: formt = get_pubkey_format(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return (decode(pub[1:33], 256), decode(pub[33:65], 256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33], 256)
        beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
        y = (P-beta) if ((beta + from_byte_to_int(pub[0])) % 2) else beta
        return (x, y)
    elif formt == 'hex': return (decode(pub[2:66], 16), decode(pub[66:130], 16))
    elif formt == 'hex_compressed':
        return decode_pubkey(safe_from_hex(pub), 'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32], 256), decode(pub[32:64], 256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64], 16), decode(pub[64:128], 16))
    else: raise Exception("Invalid format!")

def get_privkey_format(priv):
    if isinstance(priv, int_types): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")

def encode_privkey(priv, formt, vbyte=0):
    if not isinstance(priv, int_types):
        return encode_privkey(decode_privkey(priv), formt, vbyte)
    if formt == 'decimal': return priv
    elif formt == 'bin': return encode(priv, 256, 32)
    elif formt == 'bin_compressed': return encode(priv, 256, 32)+b'\x01'
    elif formt == 'hex': return encode(priv, 16, 64)
    elif formt == 'hex_compressed': return encode(priv, 16, 64)+'01'
    elif formt == 'wif':
        return bin_to_b58check(encode(priv, 256, 32), 128+int(vbyte))
    elif formt == 'wif_compressed':
        return bin_to_b58check(encode(priv, 256, 32)+b'\x01', 128+int(vbyte))
    else: raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv, 256)
    elif formt == 'bin_compressed': return decode(priv[:32], 256)
    elif formt == 'hex': return decode(priv, 16)
    elif formt == 'hex_compressed': return decode(priv[:64], 16)
    elif formt == 'wif': return decode(b58check_to_bin(priv),256)
    elif formt == 'wif_compressed':
        return decode(b58check_to_bin(priv)[:32],256)
    else: raise Exception("WIF does not represent privkey")

def add_pubkeys(p1, p2):
    f1, f2 = get_pubkey_format(p1), get_pubkey_format(p2)
    return encode_pubkey(fast_add(decode_pubkey(p1, f1), decode_pubkey(p2, f2)), f1)

def add_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    return encode_privkey((decode_privkey(p1, f1) + decode_privkey(p2, f2)) % N, f1)

def mul_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    return encode_privkey((decode_privkey(p1, f1) * decode_privkey(p2, f2)) % N, f1)

def multiply(pubkey, privkey):
    f1, f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
    pubkey, privkey = decode_pubkey(pubkey, f1), decode_privkey(privkey, f2)
    # http://safecurves.cr.yp.to/twist.html
    if not isinf(pubkey) and (pubkey[0]**3+B-pubkey[1]*pubkey[1]) % P != 0:
        raise Exception("Point not on curve")
    return encode_pubkey(fast_multiply(pubkey, privkey), f1)


def divide(pubkey, privkey):
    factor = inv(decode_privkey(privkey), N)
    return multiply(pubkey, factor)


def compress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' in f: return pubkey
    elif f == 'bin': return encode_pubkey(decode_pubkey(pubkey, f), 'bin_compressed')
    elif f == 'hex' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex_compressed')


def decompress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' not in f: return pubkey
    elif f == 'bin_compressed': return encode_pubkey(decode_pubkey(pubkey, f), 'bin')
    elif f == 'hex_compressed' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex')


def privkey_to_pubkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    if privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin', 'bin_compressed', 'hex', 'hex_compressed', 'decimal']:
        return encode_pubkey(fast_multiply(G, privkey), f)
    else:
        return encode_pubkey(fast_multiply(G, privkey), f.replace('wif', 'hex'))

privtopub = privkey_to_pubkey


def privkey_to_address(priv, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv), magicbyte)
privtoaddr = privkey_to_address


def neg_pubkey(pubkey):
    f = get_pubkey_format(pubkey)
    pubkey = decode_pubkey(pubkey, f)
    return encode_pubkey((pubkey[0], (P-pubkey[1]) % P), f)


def neg_privkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    return encode_privkey((N - privkey) % N, f)

def subtract_pubkeys(p1, p2):
    f1, f2 = get_pubkey_format(p1), get_pubkey_format(p2)
    k2 = decode_pubkey(p2, f2)
    return encode_pubkey(fast_add(decode_pubkey(p1, f1), (k2[0], (P - k2[1]) % P)), f1)


def subtract_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    k2 = decode_privkey(p2, f2)
    return encode_privkey((decode_privkey(p1, f1) - k2) % N, f1)

# Hashes


def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = ''
    try:
        digest = hashlib.new('ripemd160', intermed).digest()
    except:
        digest = RIPEMD160(intermed).digest()
    return digest


def hash160(string):
    return safe_hexlify(bin_hash160(string))


def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string, 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))


def bin_ripemd160(string):
    try:
        digest = hashlib.new('ripemd160', string).digest()
    except:
        digest = RIPEMD160(string).digest()
    return digest


def ripemd160(string):
    return safe_hexlify(bin_ripemd160(string))


def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()


def dbl_sha256(string):
    return safe_hexlify(bin_dbl_sha256(string))


def bin_slowsha(string):
    string = from_string_to_bytes(string)
    orig_input = string
    for i in range(100000):
        string = hashlib.sha256(string + orig_input).digest()
    return string


def slowsha(string):
    return safe_hexlify(bin_slowsha(string))


def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)


def num_to_var_int(x):
    x = int(x)
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253)+encode(x, 256, 2)[::-1]
    elif x < 4294967296: return from_int_to_byte(254) + encode(x, 256, 4)[::-1]
    else: return from_int_to_byte(255) + encode(x, 256, 8)[::-1]


# WTF, Electrum?
def electrum_sig_hash(message):
    padded = b"\x18Bitcoin Signed Message:\n" + num_to_var_int(len(message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)


def random_key():
    # Gotta be secure after that java.SecureRandom fiasco...
    entropy = random_string(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)


def random_electrum_seed():
    entropy = os.urandom(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)[:32]

# Encodings

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]


def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[0]


def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)


def b58check_to_hex(inp):
    return safe_hexlify(b58check_to_bin(inp))


def pubkey_to_address(pubkey, magicbyte=0):
    if isinstance(pubkey, (list, tuple)):
        pubkey = encode_pubkey(pubkey, 'bin')
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address


def is_privkey(priv):
    try:
        get_privkey_format(priv)
        return True
    except:
        return False

def is_pubkey(pubkey):
    try:
        get_pubkey_format(pubkey)
        return True
    except:
        return False

def is_address(addr):
    ADDR_RE = re.compile("^[123mn][a-km-zA-HJ-NP-Z0-9]{26,33}$")
    return bool(ADDR_RE.match(addr))


# EDCSA


def encode_sig(v, r, s):
    vb, rb, sb = from_int_to_byte(v), encode(r, 256), encode(s, 256)
    
    result = base64.b64encode(vb+b'\x00'*(32-len(rb))+rb+b'\x00'*(32-len(sb))+sb)
    return result if is_python2 else str(result, 'utf-8')


def decode_sig(sig):
    bytez = base64.b64decode(sig)
    return from_byte_to_int(bytez[0]), decode(bytez[1:33], 256), decode(bytez[33:], 256)

# https://tools.ietf.org/html/rfc6979#section-3.2


def deterministic_generate_k(msghash, priv):
    v = b'\x01' * 32
    k = b'\x00' * 32
    priv = encode_privkey(priv, 'bin')
    msghash = encode(hash_to_int(msghash), 256, 32)
    k = hmac.new(k, v+b'\x00'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v+b'\x01'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    return decode(hmac.new(k, v, hashlib.sha256).digest(), 256)


def ecdsa_raw_sign(msghash, priv):

    z = hash_to_int(msghash)
    k = deterministic_generate_k(msghash, priv)

    r, y = fast_multiply(G, k)
    s = inv(k, N) * (z + r*decode_privkey(priv)) % N

    v, r, s = 27+((y % 2) ^ (0 if s * 2 < N else 1)), r, s if s * 2 < N else N - s
    if 'compressed' in get_privkey_format(priv):
        v += 4
    return v, r, s


def ecdsa_sign(msg, priv):
    v, r, s = ecdsa_raw_sign(electrum_sig_hash(msg), priv)
    sig = encode_sig(v, r, s)
    assert ecdsa_verify(msg, sig, 
        privtopub(priv)), "Bad Sig!\t %s\nv = %d\n,r = %d\ns = %d" % (sig, v, r, s)
    return sig


def ecdsa_raw_verify(msghash, vrs, pub):
    v, r, s = vrs
    if not (27 <= v <= 34):
        return False

    w = inv(s, N)
    z = hash_to_int(msghash)

    u1, u2 = z*w % N, r*w % N
    x, y = fast_add(fast_multiply(G, u1), fast_multiply(decode_pubkey(pub), u2))
    return bool(r == x and (r % N) and (s % N))


# For BitcoinCore, (msg = addr or msg = "") be default
def ecdsa_verify_addr(msg, sig, addr):
    assert is_address(addr)
    Q = ecdsa_recover(msg, sig)
    magic = get_version_byte(addr)
    return (addr == pubtoaddr(Q, int(magic))) or (addr == pubtoaddr(compress(Q), int(magic)))


def ecdsa_verify(msg, sig, pub):
    if is_address(pub):
        return ecdsa_verify_addr(msg, sig, pub)
    return ecdsa_raw_verify(electrum_sig_hash(msg), decode_sig(sig), pub)


def ecdsa_raw_recover(msghash, vrs):
    v, r, s = vrs
    if not (27 <= v <= 34):
        raise ValueError("%d must in range 27-31" % v)
    x = r
    xcubedaxb = (x*x*x+A*x+B) % P
    beta = pow(xcubedaxb, (P+1)//4, P)
    y = beta if v % 2 ^ beta % 2 else (P - beta)
    # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
    # for a point on the curve, and so the sig is invalid
    if (xcubedaxb - y*y) % P != 0 or not (r % N) or not (s % N):
        return False
    z = hash_to_int(msghash)
    Gz = jacobian_multiply((Gx, Gy, 1), (N - z) % N)
    XY = jacobian_multiply((x, y, 1), s)
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(r, N))
    Q = from_jacobian(Q)

    # if ecdsa_raw_verify(msghash, vrs, Q):
    return Q
    # return False


def ecdsa_recover(msg, sig):
    v,r,s = decode_sig(sig)
    Q = ecdsa_raw_recover(electrum_sig_hash(msg), (v,r,s))
    return encode_pubkey(Q, 'hex_compressed') if v >= 31 else encode_pubkey(Q, 'hex')


## ripemd.py - pure Python implementation of the RIPEMD-160 algorithm.
## Bjorn Edstrom <be@bjrn.se> 16 december 2007.
##
## Copyrights
## ==========
##
## This code is a derived from an implementation by Markus Friedl which is
## subject to the following license. This Python implementation is not
## subject to any other license.
##
##/*
## * Copyright (c) 2001 Markus Friedl.  All rights reserved.
## *
## * Redistribution and use in source and binary forms, with or without
## * modification, are permitted provided that the following conditions
## * are met:
## * 1. Redistributions of source code must retain the above copyright
## *    notice, this list of conditions and the following disclaimer.
## * 2. Redistributions in binary form must reproduce the above copyright
## *    notice, this list of conditions and the following disclaimer in the
## *    documentation and/or other materials provided with the distribution.
## *
## * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
## * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
## * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
## * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
## * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
## * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
## * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
## * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
## * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
## */
##/*
## * Preneel, Bosselaers, Dobbertin, "The Cryptographic Hash Function RIPEMD-160",
## * RSA Laboratories, CryptoBytes, Volume 3, Number 2, Autumn 1997,
## * ftp://ftp.rsasecurity.com/pub/cryptobytes/crypto3n2.pdf
## */

try:
    import psyco
    psyco.full()
except ImportError:
    pass

is_python2 = sys.version_info.major == 2
#block_size = 1
digest_size = 20
digestsize = 20

try:
    range = xrange
except:
    pass

class RIPEMD160:
    """Return a new RIPEMD160 object. An optional string argument
    may be provided; if present, this string will be automatically
    hashed."""
    
    def __init__(self, arg=None):
        self.ctx = RMDContext()
        if arg:
            self.update(arg)
        self.dig = None
        
    def update(self, arg):
        """update(arg)"""        
        RMD160Update(self.ctx, arg, len(arg))
        self.dig = None
        
    def digest(self):
        """digest()"""        
        if self.dig:
            return self.dig
        ctx = self.ctx.copy()
        self.dig = RMD160Final(self.ctx)
        self.ctx = ctx
        return self.dig
    
    def hexdigest(self):
        """hexdigest()"""
        dig = self.digest()
        hex_digest = ''
        for d in dig:
            if (is_python2):
                hex_digest += '%02x' % ord(d)
            else:
                hex_digest += '%02x' % d
        return hex_digest
    
    def copy(self):
        """copy()"""        
        import copy
        return copy.deepcopy(self)



def new(arg=None):
    """Return a new RIPEMD160 object. An optional string argument
    may be provided; if present, this string will be automatically
    hashed."""    
    return RIPEMD160(arg)



#
# Private.
#

class RMDContext:
    def __init__(self):
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE,
                      0x10325476, 0xC3D2E1F0] # uint32
        self.count = 0 # uint64
        self.buffer = [0]*64 # uchar
    def copy(self):
        ctx = RMDContext()
        ctx.state = self.state[:]
        ctx.count = self.count
        ctx.buffer = self.buffer[:]
        return ctx

K0 = 0x00000000
K1 = 0x5A827999
K2 = 0x6ED9EBA1
K3 = 0x8F1BBCDC
K4 = 0xA953FD4E

KK0 = 0x50A28BE6
KK1 = 0x5C4DD124
KK2 = 0x6D703EF3
KK3 = 0x7A6D76E9
KK4 = 0x00000000

def ROL(n, x):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def F0(x, y, z):
    return x ^ y ^ z

def F1(x, y, z):
    return (x & y) | (((~x) % 0x100000000) & z)

def F2(x, y, z):
    return (x | ((~y) % 0x100000000)) ^ z

def F3(x, y, z):
    return (x & z) | (((~z) % 0x100000000) & y)

def F4(x, y, z):
    return x ^ (y | ((~z) % 0x100000000))

def R(a, b, c, d, e, Fj, Kj, sj, rj, X):
    a = ROL(sj, (a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000) + e
    c = ROL(10, c)
    return a % 0x100000000, c

PADDING = [0x80] + [0]*63

import sys
import struct

def RMD160Transform(state, block): #uint32 state[5], uchar block[64]
    x = [0]*16
    if sys.byteorder == 'little':
        if is_python2:
            x = struct.unpack('<16L', ''.join([chr(x) for x in block[0:64]]))
        else:
            x = struct.unpack('<16L', bytes(block[0:64]))
    else:
        raise "Error!!"
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    #/* Round 1 */
    a, c = R(a, b, c, d, e, F0, K0, 11,  0, x);
    e, b = R(e, a, b, c, d, F0, K0, 14,  1, x);
    d, a = R(d, e, a, b, c, F0, K0, 15,  2, x);
    c, e = R(c, d, e, a, b, F0, K0, 12,  3, x);
    b, d = R(b, c, d, e, a, F0, K0,  5,  4, x);
    a, c = R(a, b, c, d, e, F0, K0,  8,  5, x);
    e, b = R(e, a, b, c, d, F0, K0,  7,  6, x);
    d, a = R(d, e, a, b, c, F0, K0,  9,  7, x);
    c, e = R(c, d, e, a, b, F0, K0, 11,  8, x);
    b, d = R(b, c, d, e, a, F0, K0, 13,  9, x);
    a, c = R(a, b, c, d, e, F0, K0, 14, 10, x);
    e, b = R(e, a, b, c, d, F0, K0, 15, 11, x);
    d, a = R(d, e, a, b, c, F0, K0,  6, 12, x);
    c, e = R(c, d, e, a, b, F0, K0,  7, 13, x);
    b, d = R(b, c, d, e, a, F0, K0,  9, 14, x);
    a, c = R(a, b, c, d, e, F0, K0,  8, 15, x); #/* #15 */
    #/* Round 2 */
    e, b = R(e, a, b, c, d, F1, K1,  7,  7, x);
    d, a = R(d, e, a, b, c, F1, K1,  6,  4, x);
    c, e = R(c, d, e, a, b, F1, K1,  8, 13, x);
    b, d = R(b, c, d, e, a, F1, K1, 13,  1, x);
    a, c = R(a, b, c, d, e, F1, K1, 11, 10, x);
    e, b = R(e, a, b, c, d, F1, K1,  9,  6, x);
    d, a = R(d, e, a, b, c, F1, K1,  7, 15, x);
    c, e = R(c, d, e, a, b, F1, K1, 15,  3, x);
    b, d = R(b, c, d, e, a, F1, K1,  7, 12, x);
    a, c = R(a, b, c, d, e, F1, K1, 12,  0, x);
    e, b = R(e, a, b, c, d, F1, K1, 15,  9, x);
    d, a = R(d, e, a, b, c, F1, K1,  9,  5, x);
    c, e = R(c, d, e, a, b, F1, K1, 11,  2, x);
    b, d = R(b, c, d, e, a, F1, K1,  7, 14, x);
    a, c = R(a, b, c, d, e, F1, K1, 13, 11, x);
    e, b = R(e, a, b, c, d, F1, K1, 12,  8, x); #/* #31 */
    #/* Round 3 */
    d, a = R(d, e, a, b, c, F2, K2, 11,  3, x);
    c, e = R(c, d, e, a, b, F2, K2, 13, 10, x);
    b, d = R(b, c, d, e, a, F2, K2,  6, 14, x);
    a, c = R(a, b, c, d, e, F2, K2,  7,  4, x);
    e, b = R(e, a, b, c, d, F2, K2, 14,  9, x);
    d, a = R(d, e, a, b, c, F2, K2,  9, 15, x);
    c, e = R(c, d, e, a, b, F2, K2, 13,  8, x);
    b, d = R(b, c, d, e, a, F2, K2, 15,  1, x);
    a, c = R(a, b, c, d, e, F2, K2, 14,  2, x);
    e, b = R(e, a, b, c, d, F2, K2,  8,  7, x);
    d, a = R(d, e, a, b, c, F2, K2, 13,  0, x);
    c, e = R(c, d, e, a, b, F2, K2,  6,  6, x);
    b, d = R(b, c, d, e, a, F2, K2,  5, 13, x);
    a, c = R(a, b, c, d, e, F2, K2, 12, 11, x);
    e, b = R(e, a, b, c, d, F2, K2,  7,  5, x);
    d, a = R(d, e, a, b, c, F2, K2,  5, 12, x); #/* #47 */
    #/* Round 4 */
    c, e = R(c, d, e, a, b, F3, K3, 11,  1, x);
    b, d = R(b, c, d, e, a, F3, K3, 12,  9, x);
    a, c = R(a, b, c, d, e, F3, K3, 14, 11, x);
    e, b = R(e, a, b, c, d, F3, K3, 15, 10, x);
    d, a = R(d, e, a, b, c, F3, K3, 14,  0, x);
    c, e = R(c, d, e, a, b, F3, K3, 15,  8, x);
    b, d = R(b, c, d, e, a, F3, K3,  9, 12, x);
    a, c = R(a, b, c, d, e, F3, K3,  8,  4, x);
    e, b = R(e, a, b, c, d, F3, K3,  9, 13, x);
    d, a = R(d, e, a, b, c, F3, K3, 14,  3, x);
    c, e = R(c, d, e, a, b, F3, K3,  5,  7, x);
    b, d = R(b, c, d, e, a, F3, K3,  6, 15, x);
    a, c = R(a, b, c, d, e, F3, K3,  8, 14, x);
    e, b = R(e, a, b, c, d, F3, K3,  6,  5, x);
    d, a = R(d, e, a, b, c, F3, K3,  5,  6, x);
    c, e = R(c, d, e, a, b, F3, K3, 12,  2, x); #/* #63 */
    #/* Round 5 */
    b, d = R(b, c, d, e, a, F4, K4,  9,  4, x);
    a, c = R(a, b, c, d, e, F4, K4, 15,  0, x);
    e, b = R(e, a, b, c, d, F4, K4,  5,  5, x);
    d, a = R(d, e, a, b, c, F4, K4, 11,  9, x);
    c, e = R(c, d, e, a, b, F4, K4,  6,  7, x);
    b, d = R(b, c, d, e, a, F4, K4,  8, 12, x);
    a, c = R(a, b, c, d, e, F4, K4, 13,  2, x);
    e, b = R(e, a, b, c, d, F4, K4, 12, 10, x);
    d, a = R(d, e, a, b, c, F4, K4,  5, 14, x);
    c, e = R(c, d, e, a, b, F4, K4, 12,  1, x);
    b, d = R(b, c, d, e, a, F4, K4, 13,  3, x);
    a, c = R(a, b, c, d, e, F4, K4, 14,  8, x);
    e, b = R(e, a, b, c, d, F4, K4, 11, 11, x);
    d, a = R(d, e, a, b, c, F4, K4,  8,  6, x);
    c, e = R(c, d, e, a, b, F4, K4,  5, 15, x);
    b, d = R(b, c, d, e, a, F4, K4,  6, 13, x); #/* #79 */

    aa = a;
    bb = b;
    cc = c;
    dd = d;
    ee = e;

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]    

    #/* Parallel round 1 */
    a, c = R(a, b, c, d, e, F4, KK0,  8,  5, x)
    e, b = R(e, a, b, c, d, F4, KK0,  9, 14, x)
    d, a = R(d, e, a, b, c, F4, KK0,  9,  7, x)
    c, e = R(c, d, e, a, b, F4, KK0, 11,  0, x)
    b, d = R(b, c, d, e, a, F4, KK0, 13,  9, x)
    a, c = R(a, b, c, d, e, F4, KK0, 15,  2, x)
    e, b = R(e, a, b, c, d, F4, KK0, 15, 11, x)
    d, a = R(d, e, a, b, c, F4, KK0,  5,  4, x)
    c, e = R(c, d, e, a, b, F4, KK0,  7, 13, x)
    b, d = R(b, c, d, e, a, F4, KK0,  7,  6, x)
    a, c = R(a, b, c, d, e, F4, KK0,  8, 15, x)
    e, b = R(e, a, b, c, d, F4, KK0, 11,  8, x)
    d, a = R(d, e, a, b, c, F4, KK0, 14,  1, x)
    c, e = R(c, d, e, a, b, F4, KK0, 14, 10, x)
    b, d = R(b, c, d, e, a, F4, KK0, 12,  3, x)
    a, c = R(a, b, c, d, e, F4, KK0,  6, 12, x) #/* #15 */
    #/* Parallel round 2 */
    e, b = R(e, a, b, c, d, F3, KK1,  9,  6, x)
    d, a = R(d, e, a, b, c, F3, KK1, 13, 11, x)
    c, e = R(c, d, e, a, b, F3, KK1, 15,  3, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7,  7, x)
    a, c = R(a, b, c, d, e, F3, KK1, 12,  0, x)
    e, b = R(e, a, b, c, d, F3, KK1,  8, 13, x)
    d, a = R(d, e, a, b, c, F3, KK1,  9,  5, x)
    c, e = R(c, d, e, a, b, F3, KK1, 11, 10, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7, 14, x)
    a, c = R(a, b, c, d, e, F3, KK1,  7, 15, x)
    e, b = R(e, a, b, c, d, F3, KK1, 12,  8, x)
    d, a = R(d, e, a, b, c, F3, KK1,  7, 12, x)
    c, e = R(c, d, e, a, b, F3, KK1,  6,  4, x)
    b, d = R(b, c, d, e, a, F3, KK1, 15,  9, x)
    a, c = R(a, b, c, d, e, F3, KK1, 13,  1, x)
    e, b = R(e, a, b, c, d, F3, KK1, 11,  2, x) #/* #31 */
    #/* Parallel round 3 */
    d, a = R(d, e, a, b, c, F2, KK2,  9, 15, x)
    c, e = R(c, d, e, a, b, F2, KK2,  7,  5, x)
    b, d = R(b, c, d, e, a, F2, KK2, 15,  1, x)
    a, c = R(a, b, c, d, e, F2, KK2, 11,  3, x)
    e, b = R(e, a, b, c, d, F2, KK2,  8,  7, x)
    d, a = R(d, e, a, b, c, F2, KK2,  6, 14, x)
    c, e = R(c, d, e, a, b, F2, KK2,  6,  6, x)
    b, d = R(b, c, d, e, a, F2, KK2, 14,  9, x)
    a, c = R(a, b, c, d, e, F2, KK2, 12, 11, x)
    e, b = R(e, a, b, c, d, F2, KK2, 13,  8, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 12, x)
    c, e = R(c, d, e, a, b, F2, KK2, 14,  2, x)
    b, d = R(b, c, d, e, a, F2, KK2, 13, 10, x)
    a, c = R(a, b, c, d, e, F2, KK2, 13,  0, x)
    e, b = R(e, a, b, c, d, F2, KK2,  7,  4, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 13, x) #/* #47 */
    #/* Parallel round 4 */
    c, e = R(c, d, e, a, b, F1, KK3, 15,  8, x)
    b, d = R(b, c, d, e, a, F1, KK3,  5,  6, x)
    a, c = R(a, b, c, d, e, F1, KK3,  8,  4, x)
    e, b = R(e, a, b, c, d, F1, KK3, 11,  1, x)
    d, a = R(d, e, a, b, c, F1, KK3, 14,  3, x)
    c, e = R(c, d, e, a, b, F1, KK3, 14, 11, x)
    b, d = R(b, c, d, e, a, F1, KK3,  6, 15, x)
    a, c = R(a, b, c, d, e, F1, KK3, 14,  0, x)
    e, b = R(e, a, b, c, d, F1, KK3,  6,  5, x)
    d, a = R(d, e, a, b, c, F1, KK3,  9, 12, x)
    c, e = R(c, d, e, a, b, F1, KK3, 12,  2, x)
    b, d = R(b, c, d, e, a, F1, KK3,  9, 13, x)
    a, c = R(a, b, c, d, e, F1, KK3, 12,  9, x)
    e, b = R(e, a, b, c, d, F1, KK3,  5,  7, x)
    d, a = R(d, e, a, b, c, F1, KK3, 15, 10, x)
    c, e = R(c, d, e, a, b, F1, KK3,  8, 14, x) #/* #63 */
    #/* Parallel round 5 */
    b, d = R(b, c, d, e, a, F0, KK4,  8, 12, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 15, x)
    e, b = R(e, a, b, c, d, F0, KK4, 12, 10, x)
    d, a = R(d, e, a, b, c, F0, KK4,  9,  4, x)
    c, e = R(c, d, e, a, b, F0, KK4, 12,  1, x)
    b, d = R(b, c, d, e, a, F0, KK4,  5,  5, x)
    a, c = R(a, b, c, d, e, F0, KK4, 14,  8, x)
    e, b = R(e, a, b, c, d, F0, KK4,  6,  7, x)
    d, a = R(d, e, a, b, c, F0, KK4,  8,  6, x)
    c, e = R(c, d, e, a, b, F0, KK4, 13,  2, x)
    b, d = R(b, c, d, e, a, F0, KK4,  6, 13, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 14, x)
    e, b = R(e, a, b, c, d, F0, KK4, 15,  0, x)
    d, a = R(d, e, a, b, c, F0, KK4, 13,  3, x)
    c, e = R(c, d, e, a, b, F0, KK4, 11,  9, x)
    b, d = R(b, c, d, e, a, F0, KK4, 11, 11, x) #/* #79 */

    t = (state[1] + cc + d) % 0x100000000;
    state[1] = (state[2] + dd + e) % 0x100000000;
    state[2] = (state[3] + ee + a) % 0x100000000;
    state[3] = (state[4] + aa + b) % 0x100000000;
    state[4] = (state[0] + bb + c) % 0x100000000;
    state[0] = t % 0x100000000;

    pass


def RMD160Update(ctx, inp, inplen):
    if type(inp) == str:
        inp = [ord(i)&0xff for i in inp]
    
    have = int((ctx.count // 8) % 64)
    inplen = int(inplen)
    need = 64 - have
    ctx.count += 8 * inplen
    off = 0
    if inplen >= need:
        if have:
            for i in range(need):
                ctx.buffer[have+i] = inp[i]
            RMD160Transform(ctx.state, ctx.buffer)
            off = need
            have = 0
        while off + 64 <= inplen:
            RMD160Transform(ctx.state, inp[off:]) #<---
            off += 64
    if off < inplen:
        # memcpy(ctx->buffer + have, input+off, len-off);
        for i in range(inplen - off):
            ctx.buffer[have+i] = inp[off+i]

def RMD160Final(ctx):
    size = struct.pack("<Q", ctx.count)
    padlen = 64 - ((ctx.count // 8) % 64)
    if padlen < 1+8:
        padlen += 64
    RMD160Update(ctx, PADDING, padlen-8)
    RMD160Update(ctx, size, 8)
    return struct.pack("<5L", *ctx.state)


assert '37f332f68db77bd9d7edd4969571ad671cf9dd3b' == \
       new('The quick brown fox jumps over the lazy dog').hexdigest()
assert '132072df690933835eb8b6ad0b77e7b6f14acad7' == \
       new('The quick brown fox jumps over the lazy cog').hexdigest()
assert '9c1185a5c5e9fc54612808977ee8f548b2258d31' == \
       new('').hexdigest()

if sys.version_info.major == 3:
    string_types = (str)
    string_or_bytes_types = (str, bytes)
    int_types = (int, float)
    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = from_int_to_byte(int(magicbyte))+inp

        leadingzbytes = 0
        for x in inp_fmtd:
            if x != 0:
                break
            leadingzbytes += 1

        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)

    def bytes_to_hex_string(b):
        if isinstance(b, str):
            return b

        return ''.join('{:02x}'.format(y) for y in b)

    def safe_from_hex(s):
        return bytes.fromhex(s)

    def from_int_representation_to_bytes(a):
        return bytes(str(a), 'utf-8')

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        return a

    def from_string_to_bytes(a):
        return a if isinstance(a, bytes) else bytes(a, 'utf-8')

    def safe_hexlify(a):
        return str(binascii.hexlify(a), 'utf-8')

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result_bytes = bytes()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base

        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' \
            if base == 58 else b'0'
        if (pad_size > 0):
            result_bytes = padding_element*pad_size + result_bytes

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

    def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def random_string(x):
        return str(os.urandom(x))
