#!/usr/bin/env python2

# for challenge 9: implement PKCS#7 padding
def PKCS(s, n):
    """
    Appends bytes to the end of the string as specified by PKCS#7
    Returns 8-bit string
    """
    #for i in xrange(1,n+1):
    #    s += chr(i)
    s += chr(n)*n
    return s

def PKCSb(barray, n):
    """
    Appends bytes to the end of a bytearray in accordance with PKCS#7
    """
    #for i in xrange(1, n+1):
    #    barray.append(i)
    return barray.append([n]*n)

# for challenge 10: CBC Mode
from Crypto.Cipher import AES

def makeSegments(a, n):
    """
    Returns a list containing length n segments of the input a. If len(a) % n != 0, the remaining elements of a are not added to the list rather than have a partly empty segment.
    """
    num_segs = len(a) / n
    segs = []
    for i in xrange(0, num_segs*n, n):
        segs.append(a[i:i+n])
    return segs

def fixedXOR(s1, s2):
    """
    Given two bytestrings, returns a bytestring obtained by XORing the strings together byte by byte. Strings should have equal length; if they don't, the result will have length equal to the shorter of the two.
    """
    return ''.join([chr(ord(byte1) ^ ord(byte2)) for byte1, byte2 in zip(s1, s2)])

def encAESCBC(ptext, key):
    """
    Encrypts ptext under key with AES in CBC mode. Rules for input and output are the same as for the pycrypto function used as primitive (i.e., bytestrings).
    """
    # maybe this is cheating, but we'll only use it per block; we'll come back
    cipher = AES.new(key, AES.MODE_ECB)
    pad_length = (16 - (len(ptext) % 16)) % 16
    if pad_length != 0:
        ptext = PKCS(ptext, pad_length)
    blocks = makeSegments(ptext, 16)
    IV = chr(0)*16
    ctext = ''
    for block in blocks:
        output = cipher.encrypt(fixedXOR(IV, block)) # needs to be string or read-only buffer
        ctext += output
        IV = output
    return ctext

def encAESECB(ptext, key):
    """
    Encrypts ptext under key with AES in ECB mode. Rules for input and output are the same as for the pycrypto function used as primitive (i.e., bytestrings).
    """
    pad_length = (16 - (len(ptext) % 16)) % 16
    if pad_length != 0:
        ptext = PKCS(ptext, pad_length)
    segments = makeSegments(ptext, 16)
    ctext = ''
    cipher = AES.new(key, AES.MODE_ECB)
    for segment in segments:
        ctext += cipher.encrypt(segment)
    return ctext

# for challenge 11: ECB/CBC oracle
import os
import random
from collections import Counter

def encryption_oracle(ptext):
    """
    Encrypts the bytestring ptext under a randomly generated key with AES in either ECB or CBC mode. The mode is randomly chosen. The plaintext is pre- and appended with up to 10 random bytes before encryption.
    """
    key = os.urandom(16)
    f = random.randint(5, 10)
    b = random.randint(5, 10)
    front_bytes = os.urandom(f)
    back_bytes = os.urandom(b)
    ptext = front_bytes + ptext + back_bytes
    mode = random.choice(['ECB', 'CBC'])
    return encAESECB(ptext, key) if mode == 'ECB' else encAESCBC(ptext, key)

def detection_oracle(ctext):
    """
    Returns the likely mode of operation used to AES encrypt ctext.
    There's a couple things dependent on the set up: the string passed in is long enough to work in this case because we know there's at most a 10 byte prefix, so 48 bytes of plaintext is enough to cover 2 consecutive blocks regardless. That amount would have to change, depending.
    """
    ptext = 'A'*48
    ctext = encryption_oracle(ptext)
    blocks = makeSegments(ctext, 16)
    if blocks[1] == blocks[2]:
        return 'ECB'
    else:
        return 'CBC'

def stats(cipher, ptext, rounds):
    """
    Just out of interest, a function to get some basic figures on repeated blocks in ciphertexts under ECB and CBC.
    """
    avg_max = 0
    avg_repd = 0
    max = 0
    for _ in xrange(rounds):
        key = os.urandom(16)
        ctext = cipher(ptext, key)
        blocks = makeSegments(ctext, 16)
        ctr = Counter(blocks)
        repeated = filter(lambda x: x > 1, ctr.values())
        avg_max += ctr.most_common(1)[0][1]
        avg_repd += len(repeated)
        if ctr.most_common(1)[0][1] > max:
            max = ctr.most_common(1)[0][1]
    avg_max = float(avg_max) / rounds
    avg_repd = float(avg_repd) / rounds
    print 'Maximum repetitions: ' + str(max)
    print 'Avg maximum repetitions: ' + str(avg_max)
    print 'Avg number of repeated blocks: ' + str(avg_repd)

# for challenge 12: byte-at-a-time ECB decryption

def ECB_oracle(ptext, key):
    """
    Encrypts ptext + fixed_tail with AESECB.
    """
    fixed_tail = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    # key = os.urandom(16) this should be passed in
    ptext += fixed_tail.decode('base64')
    return encAESECB(ptext, key)

def findSizes(cipher):
    """
    Kind of nonsense. In the situation here, it's possible to capture both the size of the plaintext and the block size of the cipher in one go, so we may as well. As the description says, we know this already, but do it anyway.
    """
    key = os.urandom(16) # if cipher is an oracle, remove this
    start_length = len(cipher('', key))
    ptext = ''
    while True:
        ptext += 'A'
        ctext = cipher(ptext, key)
        if len(ctext) != start_length:
            block_size = len(ctext) - start_length
            target_length = start_length - len(ptext)
            return block_size, target_size

def byteXbyte_decrypt():
    ### we'll skip actually doing these steps:
    # 1. Detect ECB
    # 2. Find block size
    block_size = 16
    target_len = 138 # this could be found if not already known
    pad_length = (block_size - (target_len % block_size)) % block_size
    notch = target_len + pad_length - 1 # decrypt position
    leader = 'A'*(pad_length + target_len - 1)
    target_string = ''
    key = os.urandom(16) # fixed key for oracle
    while target_len > 0:
        target = ECB_oracle(leader, key)[notch]
        for i in xrange(256):
            scan = ECB_oracle(leader + target_string + chr(i), key)[notch]
            if scan == target:
                target_string += chr(i)
                break
        target_len -= 1
        leader = 'A'*(pad_length + target_len - 1)
    return target_string
    ## here's something interesting: during each round there are multiple possible matches, so
    # short circuiting is not something you should do. Instead, take all matches, and try one for
    # the next round, using the others as fallbacks in case the next round fails to find a match.
    # You can improve this a bit by just excluding unprintable matches and otherwise biasing toward
    # alphabetical characters.

# for challenge 13: ECB cut-and-paste

def parseCookie(c):
    """
    Accepts a bytestring assumed to be in the format
    s = 'foo=bar&baz=kux&zap=zazzle'
    and returns a dict with those key: value pairs,
    d = {'foo': bar, 'baz: kux, 'zap': zazzle}
    All values will be strings.
    """
    items = c.split('&')
    items = [item.split('=') for item in items]
    return dict(items)

def makeCookie(d):
    """
    Reverses parseCookie, just in case.
    """
    c = ''
    for member in d:
        c += member.key() + '=' + str(member.value())
    return c

from validate_email import validate_email

def profile_for(email):
    if validate_email(email):
        return 'email=' + email
    else:
        return None

def enc_profile(profile, key):
    return encAESECB(profile, key)

def dec_profile(ctext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return parseCookie(cipher.decrypt(ctext, key))

def profile_oracle(email):
    return enc_profile(profile_for(email))

def force_admin():
    # I'm skipping this for now because something about it seems unclear, but here's what it seems like they might be asking for: Use access to profile_for to get a valid profile string equal to the block size (to avoid padding being added), encrypt that, and then separately encrypt (under the same key), '&role=admin' and append that to the ciphertext. The whole thing will then decrypt to a string assigning the admin role. I'll come back to this.
    pass

# for challenge 14: byte-at-a-time ECB redux

def pf_ECB_oracle(ptext, key):
    """
    Encrypts ptext + fixed_tail with AESECB prefixed with 5 - 10 random bytes.
    """
    fixed_tail = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    pf_amt = random.randint(5, 10)
    prefix = os.urandom(pf_amt)
    # key = os.urandom(16) this should be passed in
    ptext = ''.join(map(chr, prefix)) + ptext + fixed_tail.decode('base64')
    return encAESECB(ptext, key)

def pf_byteXbyte_decrypt():
    pass

# for challenge 15: PKCS#7 Validation
import string

def valid_PKCS(text):
    """
    Returns true if text is padded with valid PKCS#7 padding or if no padding is present. Assumes text otherwise contains only printable characters.
    """
    tail = ord(text[-1])
    expected_pad = chr(tail)*tail
    if 1 <= tail and tail <= 15: # padding is present
        if text[len(text)-tail:] == expected_pad and text[:len(text)-tail] in string.printable:
            return True
        else:
            raise ValueError('Bad padding')
    else: # no padding; trivially valid
        return True

def check_and_strip_PKCS(text):
    if valid_PKCS(text):
        return text[:len(text)-ord(text[-1])]

# for challenge 16: CBC Bitflipping
