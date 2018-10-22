#!/usr/bin/env python2
import os
import random
fixed_oracle_key = os.urandom(16)
nonce = os.urandom(8)
from set2 import fixedXOR


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
