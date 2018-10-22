#!/usr/bin/env python2
import os
import random
fixed_oracle_key = os.urandom(16)
nonce = os.urandom(8)
from set2 import fixedXOR, make_segments, PKCS, check_and_strip_PKCS
from Crypto.Cipher import AES


# for challenge 25: Break AES CTR Random Access

def get_ctext():
    with open('25.txt', 'r') as f:
        lines = f.readlines()
    lines = [line.strip() for line in lines]
    return AESCTR(''.join(lines), fixed_oracle_key, nonce)

def AESCTRedit(ctext, key, offset, splice):
    count = offset / 16
    pre_edit = AESCTR(ctext, key, nonce)
    edit = pre_edit[:offset] + splice + pre_edit[offset+len(splice):]
    return AESCTR(edit, key, nonce)

def edit(ctext, offset, splice):
    return AESCTRedit(ctext, fixed_oracle_key, offset, splice)

def recover_plaintext():
    ctext = get_ctext()
    keystream = edit(ctext, 0, chr(0)*len(ctext))
    return fixedXOR(keystream, ctext)

# for challenge 26: CTR Bitflipping

def generate_and_encrypt_usrdata(data):
    # quote out tokens
    data = data.replace(";", "';'")
    data = data.replace("=", "'='")
    prefix = "comment1=Cooking%20MCs;userdata="
    postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
    fulldata = prefix + data + postfix
    return AESCTR(fulldata, fixed_oracle_key, nonce)

def is_admin(ctext):
    ptext = AESCTR(ctext, fixed_oracle_key, nonce)
    splits = ptext.split(';')
    lu = dict([item.split('=') for item in splits])
    return bool(lu.get('admin', False))

def force_admin():
    data = "Gotch;dmi=rue"
    ctext = generate_and_encrypt_usrdata(data)
    maul = '\x00'*32 + '\x00\x00\x00\x00\x00F\x00F\x00\x00\x00I\x00S\x00\x00\x00' + '\x00'*42
    submission = fixedXOR(ctext, maul)
    if is_admin(submission):
        print 'Yessssss'
    else:
        print 'Aw, peas.'


# for challenge 27: Recover key from CBC with IV=Key

def encAESCBC(ptext, key):
    """
    Encrypts ptext under key with AES in CBC mode. Rules for input and output are the same as for the pycrypto function used as primitive (i.e., bytestrings).
    """
    cipher = AES.new(key, AES.MODE_ECB)
    pad_length = 16 - (len(ptext) % 16)
    ptext = PKCS(ptext, pad_length)
    blocks = make_segments(ptext, 16)
    IV = key
    ctext = ''
    for block in blocks:
        output = cipher.encrypt(fixedXOR(IV, block)) # needs to be string or read-only buffer
        ctext += output
        IV = output
    return ctext

def decAESCBC(ctext, key):
    blocks = make_segments(ctext, 16)
    IV = key
    cipher = AES.new(key, AES.MODE_ECB)
    ptext = ''
    for block in blocks:
        ptext += fixedXOR(IV, cipher.decrypt(block))
        IV = block
    return check_and_strip_PKCS(ptext)

def ascii_compliant(text):
    for char in text:
        if ord(char) > 128:
            raise ValueError('Non-ascii characters present: ' + text)
    return True

def decrypt_and_validate(ctext):
    blocks = make_segments(ctext, 16)
    IV = key
    cipher = AES.new(fixed_oracle_key, AES.MODE_ECB)
    ptext = ''
    for block in blocks:
        ptext += fixedXOR(IV, cipher.decrypt(block))
        IV = block
    ascii_compliant(ptext)
    return check_and_strip_PKCS(ptext)

def recover_key():
    ptext = 'A'*16 + 'B'*16 + 'C'*16
    ctext = encAESCBC(ptext, fixed_oracle_key)
    maul = ctext[:16] + '\x00'*16 + ctext[:16]
    try:
        ptext2 = decrypt_and_validate(maul)
    except ValueError as e:
        ptext = e.message[30:]
    block1 = ptext[:16]
    block3 = ptext[32:]
    key = fixedXOR(block1, block3)
    print 'Key recovered: ' + key
    print 'Actual key: ' + fixed_oracle_key
    

# for challenge 28: SHA-1 Keyed MAC
from struct import pack, unpack

def sha1(data):
    """ Returns the SHA1 sum as a 40-character hex string """
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    # After the data, append a '1' bit, then pad data to a multiple of 64 bytes
    # (512 bits).  The last 64 bits must contain the length of the original
    # string in bits, so leave room for that (adding a whole padding block if
    # necessary).
    padding = chr(128) + chr(0) * (55 - len(data) % 64)
    if len(data) % 64 > 55:
        padding += chr(0) * (64 + 55 - len(data) % 64)
    padded_data = data + padding + pack('>Q', 8 * len(data))

    thunks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in thunks:
        w = list(unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = rol(a, 5) + f + e + k + w[i] & 0xffffffff, \
                            a, rol(b, 30), c, d

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def SHAMAC(message, key):
    return sha1(key + message)

def valid_MAC(message, mac, key):
    return sha1(key + message) == mac


# for challenge 29: Break SHA-1 MAC with length extension


# for challenge 30: Break MD4 MAC with length extension


# for challenge 31: Implement HMAC-SHA-1 and break with artificial timing leak


# for challenge 32: Ditto, but less articial timing leak
