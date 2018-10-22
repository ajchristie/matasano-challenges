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
        return valid_PKCS(ptext)
    except ValueError:
        return False

def padding_attack():
    ctext, IV = send_token()
    cblocks = [IV]
    cblocks.extend(make_segments(ctext, 16))
    maul = '\x00'*16
    pblocks = []
    for i in xrange(len(cblocks)):
        P = ''
        C = cblocks[i+1]  # block to be decrypted
        padding_value = 0
        tail_value = '\x00'
        for j in xrange(15, -1, -1): # break block
            maul = maul[:j+1] + tail_value*padding_value
            attack_value = 0
            for k in xrange(256): # scan for valid padding
                maul[j] = chr(k)
                sub = maul + C
                if padding_oracle(sub):
                    if j == 15: # check for edge case: valid padding != \x01
                        subsub = sub[:j-1] + chr(ord('\xFF') ^ ord(sub[j-1])) + sub[j:]
                        if padding_oracle(subsub): # not in edge case
                            attack_value = k
                            break
                    attack_value = k
                    break
            else: # full loop with no match
                raise ValueError('No match found for %s, %s' % (j, k))
            # if we make it here, a match was found and the padding is as expected
            padding_value += 1
            P += chr(((padding_value) ^ attack_value) ^ ord(C[j]))
            tail_value = chr(((padding_value) ^ attack_value) ^ (padding_value + 1))
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
    for i in xrange(0, len(ptext), 16):
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
    pass
    # ETAOIN SHRDLU. I'll skip this for now, since the method that first occurred to me was the one
    # in the next challenge anyway. I'll come back eventually.


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
    def __init__(self, seed=None):
        self.w = 32
        self.n = 624
        self.state = [0]*self.n
        self.index = self.n + 1
        if seed is not None:
            self.seed_state(seed)
        else:
            self.seed_state(5489)

    def seed_state(self, value):
        self.index = self.n
        self.state[0] = value
        for i in xrange(1, self.n):
            self.state[i] = ((1 << self.w) - 1) & (
                1812433253 * (self.state[i-1] ^ (self.state[i-1] >> (self.w - 2))) + i)

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.state[self.index]
        y = y ^ ((y >> 11) & 0xFFFFFFFF)
        y = y ^ ((y << 7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ (y >> 18)
        self.index += 1
        return y

    def twist(self):
        for i in xrange(self.n):
            x = (self.state[i] & (((1 << self.w) - 1) & ~((1 << 31) - 1))) + (self.state[(i+1) % (self.n)] & ((1 << 31) - 1))
            xA = x >> 1
            if x % 2:
                xA %= 0x9908B0DF
            self.state[i] = self.state[(i + 397) % self.n] ^ xA
        self.index = 0


# for challenge 22: Crack an MT19937 seed
import time

def a_value():
    generator = MT19937()
    wait_time = random.randint(20, 60)
    time.sleep(wait_time)
    generator.seed_state(int(time.time()))
    wait_time = random.randint(40, 1000)
    print "You'll be waiting " + str(wait_time) + " seconds."
    time.sleep(wait_time)
    number = generator.extract_number()
    print "Here you go: " + str(number)
    return number

def catch_seed():
    time1 = int(time.time())
    number = a_value()
    time2 = int(time.time())
    for i in xrange(time2, time1, -1):
        t = MT19937(i)
        first_out = t.extract_number()
        if first_out == number:
            print 'Winner: ' + str(seed)
            print 'First output with that seed: ' + str(first_out)
            print 'Target: ' + str(number)
            print 'Nobody gets that lucky.'
    else:
        print 'Oopsidoozio! No matches.'

# for challenge 23: Clone an MT19937 from output

def temper(y):
    y = y ^ ((y >> 11) & 0xFFFFFFFF) # bits 1 through 21 affected by 12 - 32
    y = y ^ ((y << 7) & 0x9D2C5680)  # bits 8 through 32 by 1 - 24
    y = y ^ ((y << 15) & 0xEFC60000) # bits 18 through 32 by 2 - 16
    y = y ^ (y >> 18) # bits 1 through 14 by 19 - 32
    return y

def untemper(y):
    y = y ^ (y >> 18)
    y = y ^ ((y << 15) & 0xEFC60000)
    window = 0x0000000F
    while window <= 0xF0000000:
        inter = (y << 7) & 0x9D2C5680
        y ^= (inter & window)
        window *= 16
    window /= 16
    while window >= 0x0000000F:
        inter = (y >> 11) & 0xFFFFFFFF
        y ^= (inter & window)
        window /= 16
    return y

def rebuild_state(outputs): # assumes outputs is in append order of output from twister
    state = []
    for i in xrange(len(outputs)):
        value = untemper(outputs[i])
        state.append(value)
    return state

def clone_twister(outputs):
    state = rebuild_state(outputs)
    clone = MT19937()
    clone.state = state
    clone.index = 0
    return clone


# for challenge 24: Create & break MT19937 stream cipher

def MTCTR(ptext, seed):
    t = MT19937(seed)
    ctext = ''
    for i in xrange(0, len(ptext), 4):
        ctext += fixedXOR(ptext[i:i+4], struct.pack('l', t.extract_number()))
    return ctext

def a_ctext(s):
    prefix_size = random.randint(1, 15)
    prefix = os.urandom(prefix_size)
    ptext = prefix + 'AAAAAAAAAAAAAA'
    return MTCTR(ptext, s)

def recover_key():
    seed = random.randint(1, 65536)
    ctext = a_ctext(seed)
    for i in xrange(65536):
        ptext = MTCTR(ctext, i)
        if ptext[-14:] == 'AAAAAAAAAAAAAA':
            print 'Seed match: ' + str(i)
            print 'Actual seed: ' + str(seed)
            return None
    print 'No match found!!'
    return None

def make_token():
    t = MT19937(time.time())
    raw_token = ''
    for _ in xrange(32):
        raw_token += struct.pack('l', t.extract_number())
    return raw_token.encode('base64')

def is_from_time(token):
    raw_token = token.decode('base64')
    time = time.time()
    # we'll assume any prospective token was created in the last hour... could be something else
    t = MT19937()
    print 'Looking to match: ' + token
    for i in xrange(3600):
        t.seed_state(time - i)
        comp = ''
        for _ in xrange(32):
            comp += struct.pack('l', t.extract_number())
        if comp == raw_token:
            print 'Matching token found: ' + comp
            print 'Seed: ' + str(time - i)
            return None
    print 'No matches. Either not a token or created more than an hour ago.'
