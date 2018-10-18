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

def padding_attack(): # this still needs a fallback routine and to be debugged
    ctext, IV = send_token()
    cblocks = [IV]
    cblocks.extend(make_segments(ctext, 16))
    maul = '\x00'*15
    pblocks = []
    for i in xrange(len(cblocks)):
        P = ''
        C = cblocks[i+1]
        padding_value = 1
        attack_value = 0
        for j in xrange(16):
            maul = maul[:15-j]+ chr(padding_value)*j
            for k in xrange(1,256):
                maul[j] = chr(k)
                submission = maul + C
                if padding_oracle(submission):
                    attack_value = k
                    break
                P += chr((padding_value ^ k) ^ ord(C[j]))
            padding_value += 1
        pblocks.append(P)
    return ''.join(pblocks)


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
    if len(ptext) % 16 != 1:
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
    # ETAOIN SHRDLU


# for challenge 20: Break fixed-nonce CTR Vigenere style


# for challenge 21: Implement MT19937 Mersenne Twister RNG


# for challenge 22: Crack an MT19937 seed


# for challenge 23: Clone an MT19937 from output


# for challenge 24: Create & break MT19937 stream cipher
