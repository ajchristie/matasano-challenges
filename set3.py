#!/usr/bin/env python2

# for challenge 17: CBC padding oracle attack
import os
import random
fixed_oracle_key = os.urandom(16)
from set2 import encAESCBC, decAESCBC, valid_PKCS, make_segments, fixedXOR
from Crypto.Cipher import AES

def send_token():
    tokens = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
               'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
               'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
               'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
               'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
               'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
               'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
               'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
               'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
               'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
    token = random.choice(tokens)
    IV = chr(0)*16 # remember to change this if you randomize IVs
    return encAESCBC(token.decode('base64'), fixed_oracle_key), IV

def decAESCBC_keep_padding(ctext, key):
    blocks = make_segments(ctext, 16)
    IV = chr(0)*16
    cipher = AES.new(key, AES.MODE_ECB)
    ptext = ''
    for block in blocks:
        ptext += fixedXOR(IV, cipher.decrypt(block))
        IV = block
    return ptext

def padding_oracle(ctext):
    ptext = decAESCBC_keep_padding(ctext, fixed_oracle_key)
    try:
        return valid_PKCS(ctext)
    except ValueError:
        return False



# for challenge 18: Implement CTR mode
import struct

def AESCTR(ptext, key, nonce=None):
    if nonce is None:
        nonce = '\x00'*8
    cipher = AES.new(key, AES.MODE_ECB)
    ctext = ''
    counter = 0
    IV = nonce + struct.pack('<q', counter)
    num_blocks = len(ptext) / 16
    if len(ptext) % 16 != 1:
        num_blocks += 1
    for i in xrange(0, num_blocks*16, 16):
        ctext += fixedXOR(ptext[i:i+16], cipher.encrypt(IV))
        counter += 1
        IV = nonce + struct.pack('<q', counter)
    return ctext

# for challenge 19: Break fixed-nonce CTR with substitutions
