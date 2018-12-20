#!/usr/bin/env python2

# for challenge 9: implement PKCS#7 padding
def PKCS(s, n):
    """
    Appends bytes to the end of the string as specified by PKCS#7
    Returns 8-bit string
    """
    s += chr(n)*n
    return s

def PKCSb(barray, n):
    """
    Appends bytes to the end of a bytearray in accordance with PKCS#7
    """
    return barray.append([n]*n)

# for challenge 10: CBC Mode
from Crypto.Cipher import AES

def make_segments(a, n):
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
    cipher = AES.new(key, AES.MODE_ECB)
    pad_length = 16 - (len(ptext) % 16)
    ptext = PKCS(ptext, pad_length)
    blocks = make_segments(ptext, 16)
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
    pad_length = 16 - (len(ptext) % 16)
    ptext = PKCS(ptext, pad_length)
    segments = make_segments(ptext, 16)
    ctext = ''
    cipher = AES.new(key, AES.MODE_ECB)
    for segment in segments:
        ctext += cipher.encrypt(segment)
    return ctext

# for challenge 11: ECB/CBC oracle
import os
import random
from collections import Counter
fixed_oracle_key = os.urandom(16)

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

def detection_oracle():
    """
    Returns the likely mode of operation used to AES encrypt ctext.
    There's a couple things dependent on the set up: the ptext string is long enough to work in this case because we know there's at most a 10 byte prefix, so 48 bytes of plaintext is enough to cover 2 consecutive blocks regardless. That amount would have to change, depending.
    """
    ptext = 'A'*48
    ctext = encryption_oracle(ptext)
    blocks = make_segments(ctext, 16)
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
        blocks = make_segments(ctext, 16)
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

def ECB_oracle(ptext):
    """
    Encrypts ptext + fixed_tail with AESECB.
    """
    fixed_tail = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    ptext += fixed_tail.decode('base64')
    return encAESECB(ptext, fixed_oracle_key)

def find_sizes(cipher):
    """
    In the situation here, it's possible to capture both the size of the plaintext and the block size of the cipher in one go, so we may as well. As the description says, we know this already, but do it anyway.
    """
    start_length = len(cipher('', fixed_oracle_key))
    ptext = ''
    while True:
        ptext += 'A'
        ctext = cipher(ptext, fixed_oracle_key)
        if len(ctext) != start_length:
            block_size = len(ctext) - start_length
            target_size = start_length - len(ptext)
            return block_size, target_size

def byteXbyte_decrypt():
    ### we'll skip actually doing these steps:
    # 1. Detect ECB
    # 2. Find block size (& target length)
    # In other circumstances use the previous function in place of the first two assignments below.
    block_size = 16
    target_len = 138
    pad_length = (block_size - (target_len % block_size)) % block_size
    notch = target_len + pad_length - 1 # decrypt position
    leader = 'A'*(pad_length + target_len - 1)
    target_string = ''
    while target_len > 0:
        target = ECB_oracle(leader)[notch-block_size:notch+1]
        for i in xrange(256):
            scan = ECB_oracle(leader + target_string + chr(i))[notch-block_size:notch+1]
            if scan == target:
                target_string += chr(i)
                break
        target_len -= 1
        leader = 'A'*(pad_length + target_len - 1)
    return target_string

# for challenge 13: ECB cut-and-paste

def parse_cookie(c):
    """
    Accepts a bytestring assumed to be in the format
    s = 'foo=bar&baz=kux&zap=zazzle'
    and returns a dict with those key: value pairs --
    d = {'foo': bar, 'baz: kux, 'zap': zazzle}
    All values will be strings.
    """
    items = c.split('&')
    items = [item.split('=') for item in items]
    return dict(items)

def profile_for(email):
    # eat tokens
    email = ''.join(email.split('='))
    email = ''.join(email.split('&'))
    return 'email=' + email + '&uid=10&role=user'

def enc_profile(profile):
    return encAESECB(profile, fixed_oracle_key)

def dec_profile(ctext):
    cipher = AES.new(fixed_oracle_key, AES.MODE_ECB)
    return parse_cookie(check_and_strip_PKCS(cipher.decrypt(ctext)))

def profile_oracle(email):
    return enc_profile(profile_for(email))

def force_admin():
    email = 'MrX@gmail.com'
    ciphertext1 = profile_oracle(email)
    evilmail = '0000000000admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@gmail.com'
    ciphertext2 = profile_oracle(evilmail)
    submission = ciphertext1[:32] + ciphertext2[16:32]
    result = dec_profile(submission)
    if result['role'] == 'admin':
        print 'Success!: ' + str(result)
    else:
        print 'Shucks: ' + str(result)

# for challenge 14: byte-at-a-time ECB redux
pf_amt = random.randint(5, 10)
random_prefix = os.urandom(pf_amt)

def pf_ECB_oracle(ptext):
    """
    Encrypts ptext + fixed_tail with AESECB prefixed with 5 - 10 random bytes.
    """
    fixed_tail = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    ptext = random_prefix + ptext + fixed_tail.decode('base64')
    return encAESECB(ptext, fixed_oracle_key)

def pf_byteXbyte_decrypt():
    ## I'm going to pass on this one for now, since the challenge seems to say the same random
    # prefix is always used. If so, the method used above will work after writing a new find_sizes
    # function that will also find the size of the prefix, which is very doable.
    # Then, everything in byteXbyte_decrypt can be shifted by that amount and will work
    # in this case too.
    pass

# for challenge 15: PKCS#7 Validation

def valid_PKCS(text):
    """
    Returns true if text is padded with valid PKCS#7 padding.
    """
    tail = ord(text[-1])
    if 1 <= tail and tail <= 16:
        expected_pad = chr(tail)*tail
        if text[len(text)-tail:] == expected_pad:
            return True
        else:
            raise ValueError('Bad padding')
    else: # no padding; invalid
        raise ValueError('Bad Padding')

def check_and_strip_PKCS(text):
    if valid_PKCS(text):
        return text[:len(text)-ord(text[-1])]

# for challenge 16: CBC Bitflipping

def decAESCBC(ctext, key):
    blocks = make_segments(ctext, 16)
    IV = chr(0)*16
    cipher = AES.new(key, AES.MODE_ECB)
    ptext = ''
    for block in blocks:
        ptext += fixedXOR(IV, cipher.decrypt(block))
        IV = block
    return check_and_strip_PKCS(ptext)


def generate_and_encrypt_usrdata(data):
    # quote out tokens
    data = data.replace(";", "';'")
    data = data.replace("=", "'='")
    prefix = "comment1=Cooking%20MCs;userdata="
    postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
    fulldata = prefix + data + postfix
    return encAESCBC(fulldata, fixed_oracle_key)

def is_admin(ctext):
    ptext = decAESCBC(ctext, fixed_oracle_key)
    splits = ptext.split(';')
    lu = dict([item.split('=') for item in splits])
    return bool(lu.get('admin', False))

def force_admin2():
    data = "0000000000000000;dmi=rue"
    ctext = generate_and_encrypt_usrdata(data)
    maul = '\x00'*32 + '\x00\x00F\x00\x00\x00I\x00S' + '\x00'*81
    submission = fixedXOR(ctext, maul)
    if is_admin(submission):
        print 'Yessssss'
    else:
        print 'Aw, peas.'
