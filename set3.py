#!/usr/bin/env python2

# for challenge 17: CBC padding oracle attack
import os
import random
fixed_oracle_key = os.urandom(16)
from set2 import encAESCBC, decAESCBC, valid_PKCS

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
    return encAESCBC(token, fixed_oracle_key), IV

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
    ptext = decAESCBC_keep_padding(ctext)
    return valid_PKCS(ptext)
