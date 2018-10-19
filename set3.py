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

def padding_attack(): # this still needs to be debugged
    ctext, IV = send_token()
    cblocks = [IV]
    cblocks.extend(make_segments(ctext, 16))
    maul = '\x00'*16
    pblocks = []
    for i in xrange(len(cblocks)):
        P = ''
        C = cblocks[i+1]
        padding_value = 1
        for j in xrange(15, -1, -1):
            maul = maul[:j] + chr(padding_value)*j
            attack_value = 0
            for k in xrange(1,256):
                maul[j] = chr(k)
                submission = maul + C
                if padding_oracle(submission):
                    attack_value = k
                    break
            padding_value += 1
            edge_check = True if j == 15 else False
            while edge_check:
                index = j-1
                for k in xrange(1, 256):
                    temp = maul[:index] + chr(k)
                    submission = temp + C
                    if padding_oracle(submission):
                        padding_value += 1
                        attack_value = k
                        index -= 1
                    else:
                        edge_check = False
            P += chr((padding_value ^ attack_value) ^ ord(C[j]))
        pblocks.append(P)
    return ''.join(pblocks), decAESCBC(ctext, fixed_oracle_key)

# for challenge 18: Implement CTR mode
import struct

def AESCTR(ptext, key, nonce=None): # nonce should be little endian bytestring
    if nonce is None:
        nonce = chr(0)*8
    cipher = AES.new(key, AES.MODE_ECB)
    ctext = ''
    counter = 0
    IV = nonce + struct.pack('<q', counter)
    num_blocks = len(ptext) / 16
    if len(ptext) % 16 != 0:
        num_blocks += 1
    for i in xrange(0, num_blocks*16, 16):
        ctext += fixedXOR(ptext[i:i+16], cipher.encrypt(IV))
        counter += 1
        IV = nonce + struct.pack('<q', counter)
    return ctext

# for challenge 19: Break fixed-nonce CTR with substitutions

def make_ciphertexts():
    ptexts = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
              'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
              'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
              'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
              'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
              'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
              'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
              'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
              'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
              'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
              'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
              'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
              'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
              'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
              'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
              'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
              'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
              'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
              'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
              'U2hlIHJvZGUgdG8gaGFycmllcnM/',
              'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
              'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
              'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
              'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
              'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
              'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
              'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
              'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
              'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
              'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
              'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
              'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
              'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
              'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
              'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
              'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']
    return [AESCTR(ptext.decode('base64'), fixed_oracle_key) for ptext in ptexts]

def CTR_break1():
    ctexts = make_ciphertexts()
    # ETAOIN SHRDLU. Skip this for now, since the method that forst occurred to me was the one in
    # the next challenge anyway. I'll come back.


# for challenge 20: Break fixed-nonce CTR Vigenere style

def loadCT():
    with open('20.txt', 'r') as f:
        ctexts = f.readlines()
    ctexts = [line.strip() for line in ctexts]
    return ctexts

def CTR_break2():
    ctexts = loadCT()
    min_length = min([len(ctext) for ctext in ctexts])
    num_blocks = min_length / 16
    decrypt_length = num_blocks*16
    vigs = []
    for i in xrange(0, decrypt_length, 16):
        vig = [ctext[i:i+16] for ctext in ctexts]
        vigs.append(vig)
    ptexts = []
    keys = []
    for vig in vigs:
        key, decrypted = breakVig(vig)
        keys.append(key)
        ptexts.append(make_segments(decrypted, 16))
    ptexts = zip(*ptexts)
    print 'Maximum overlap in samples: ' + str(min_length)
    print 'Decrypt length: ' + str(decrypt_length)
    for i in xrange(len(ptexts)):
        print 'Ciphertext: ' + ctexts[i]
        print 'Plaintext: ' + ptexts[i]
        print '\n'

# for challenge 21: Implement MT19937 Mersenne Twister RNG

class MT19937:
    __init__(self, seed=None):
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = int(0x9908B0DF)
        self.u = 11
        self.d = int(0xFFFFFFFF)
        self.s = 7
        self.b = int(0x9D2C5680)
        self.t = 15
        self.c = int(0xEFC60000)
        self.l = 18
        self.f = 1812433253
        self.state = []
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = ((1 << self.w) - 1) & ~(self.lower_mask)
        if seed:
            self.seed_state(seed)
        else:
            self.seed_state(5489)

    def seed_state(value):
        self.index = self.n
        self.state[0] = value
        for i in xrange(1, self.n):
            self.state[i] = ((1 << self.w) - 1) & (
                self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w - 2))) + i)

    def extract_number():
        if self.index >= self.n:
            self.twist()
        y = self.state[index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return ((1 << self.w) - 1) & y

    def twist():
        for i in xrange(self.n):
            x = (self.state[i] & self.upper_mask) + (self.state[i+1 % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA %= self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xA
        self.index = 0


# for challenge 22: Crack an MT19937 seed


# for challenge 23: Clone an MT19937 from output


# for challenge 24: Create & break MT19937 stream cipher
