#!/usr/bin/env python2
import random
import hashlib
from set5 import modinv, RSA_decrypt, RSA_encrypt, num_convert

# for challenge 41: Implement an unpadded message recovery oracle
# This is just an easy 'dangers of malleability' exercise. Skipping for now.


# for challenge 42: Bleichenbacher's e=3 RSA attack
HASH_ASN1 = {
    'MD5': b('\x30\x20\x30\x0c\x06\x08\x2a\x86'
             '\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'),
    'SHA-1': b('\x30\x21\x30\x09\x06\x05\x2b\x0e'
               '\x03\x02\x1a\x05\x00\x04\x14'),
    'SHA-256': b('\x30\x31\x30\x0d\x06\x09\x60\x86'
                 '\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'),
    'SHA-384': b('\x30\x41\x30\x0d\x06\x09\x60\x86'
                 '\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30'),
    'SHA-512': b('\x30\x51\x30\x0d\x06\x09\x60\x86'
                 '\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'),
}

def faulty_pad_check(message, signature, pub_key, modulus):
    if signature[:2] != '\x00\x01':
        return False
    i = 2
    while signature[i] == '\xFF':
        i += 1
    if i == 2:
        return False
    if signature[i] != '\x00':
        return False
    if signature[i+1:i+16] != HASH_ASN1['SHA-1']:
        return False
    if signature[i+16:i+26] != hashlib.sha1(message).digest():
        return False
    return True

def forge_signature(message):
    hash = hashlib.sha1(message).digest()
    padding = '\x00\x01\xFF\xFF\xFF\xFF\x00' + HASH_ASN1['SHA-1'] + hash
    # these last lines could be looped to make sure the shift is enough for arbitrary messages
    # i.e., actually check it before returning
    cube = int(padding.encode('hex'), 16) * (16 * (128 - len(padding)))
    return nth_root(cube, 3) + 1 # since nth_root returns _under_ the true root

def nth_root(x, n): # make sure x != 0
    """ Returns nearest integer < true nth root of x """
    root = 1
    while root**n < x:
        root *= 2
    root /= 2
    for i in xrange(len(bits(root)) - 4, -1, -1):
        root += (2**i)
        if root > x:
            root -= (2**i)
    return root


# for challenge 43: DSA key recovery from nonce

# Parameters, which I'll let be globals rather than passing them around everywhere:
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def generate_DSA_keys():
    private = random.SystemRandom().randint(1, q - 1)
    return private, pow(g, ephemeral, p)

# below, we pass in the message hash because for some reason I wasn't getting the sha1 for the
# message given in the challenge

def sign(mhash, priv_key):
    r = 0
    s = 0
    sha = hashlib.sha1()
    while r == 0 or s == 0:
        ephemeral = random.SystemRandom().randint(2, q - 1)
        r = pow(g, ephemeral, p) % q
        H = int(mhash, 16)
        s = (modinv(ephemeral, q) * (H + (priv_key * r))) % q
    return r, s

def sign_k(mhash, priv_key, k):
    r = 0
    s = 0
    sha = hashlib.sha1()
    while r == 0 and s == 0:
        r = pow(g, k, p) % q
        H = int(mhash, 16)
        s = (modinv(k, q) * (H + (priv_key * r))) % q
    return r, s

def verify(mhash, signature, pub_key):
    r, s = signature[0], signature[1]
    if r == 0 or s == 0:
        return False
    w = modinv(s, q)
    H = int(mhash, 16)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(pub_key, u2, p)) % p) % q
    return True if v == r else False

def recover_key(mhash, signature, k):
    r, s = signature[0], signature[1]
    return (((s * k) - mhash) * invmod(r, q)) % q

pubkey43 = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

message = 'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch'

message_hash = 'd2d0714f014a9784047eaeccf956520045c45265'

target_r = 548099063082341131477253921760299949438196259240
target_s = 857042759984254168557880549501802188789837994940

def recover_key_from_nonce():
    r, s = 0, 0
    for i in xrange(65536):
        key = recover_key(message_hash, [target_r, target_s], i)
        alt_pub = pow(g, key, p)
        if alt_pub == pubkey43:
            print 'Key found: ' + str(key)
            print 'Its fingerprint: ' + hashlib.sha1(key).hexdigest()
            print 'Given fingerprint: 0954edd5e0afe5542a4adf012611a91912a3ec16'


# for challenge 44: DSA recovery from repeated nonce
from collections import Counter

#pubkey44 = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
# sha-1 key (hex) fingerprint: ca8f6f7c66fa362d40760d135b763eb8527d3d52

def recover_key_rep_nonce():
    with open('44.txt', 'r') as f:
        sigs = f.readlines()
    sigs = [line.strip() for line in sigs]
    rs = [sigs[i+2] for i in xrange(0, len(sigs), 4)]
    sigs = [sigs[i:i+3] for i in xrange(0, len(sigs), 4)]
    # find the repeated nonce
    ctr = Counter(rs)
    r = ctr.most_common(1)[0][0]
    reps = []
    for sig in sigs:
        if sig[2] == r:
            reps.append(sig)
    # recover nonce
    m1 = int(reps[0][3][3:], 16)
    m2 = int(reps[1][3][3:], 16)
    s1 = int(reps[0][1][3:])
    s2 = int(reps[1][1][3:])
    num = (m1 - m2) % q
    den = (s1 - s2) % q
    k = num * invmod(den, q)
    # recover key
    key = recover_key(reps[0][0], [reps[0][2], reps[0][1]], k)
    print 'Key recovered: ' + str(key)
    print 'Its fingerprint: ' + hashlib.sha1(key).hexdigest()
    print 'Target fingerprint: ca8f6f7c66fa362d40760d135b763eb8527d3d52'


# for challenge 45: DSA parameter tampering
# Setting g = 0 won't work because there's a check for r = 0 at the front of the verify method.
# If that weren't there, verifier = 0 and everything would verify.
# Taking g = 1 will still pass, however...


# for challenge 46: RSA parity oracle
import decimal # the parity decrypt can have issues without control over precision
p46 = 0x00e13584e1373c6d74db0a5b3770dc3b9c50d4d741e92ec71ffac97e5d77be43c9b462e2705aa03e8be8d1feee429eef93a8f87e1c0f27fb123e975cfb785f3371
q46 = 0x00c2c9c5499a60e3d08f6148af2da4e159b47a01bd5cf9663991f36689ec420af5ca088fc982dca34b8952a63a2bbc312e8b026b3a2431bad235725bc00dc5076f
N46 = p46 * q46
e46 = 65537
d46 = 0x009c3f23daedccb8118941da043d1d2d466c56de1840a774c9557b7c7f87a66e7eafad9afc146bc27680398cdc008490c928d15211b7635e7b9e11d391a4afec10298a13f488fbc43a048a56860e63833365d46f7d99dd211d07a618d151d8671b123591b75b264cc8281bb452ac8228247313805db69233456507af3085480fa1
message46 = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='

def make_ctext():
    return RSA_encrypt(int(message46.decode('base64').encode('hex'), 16), e46, N46)

def RSA_parity(message):
    return (RSA_decrypt(message, d46, p46, q46) % 2) == 0

def parity_decrypt():
    k = 1024 # more generally, bit length of the RSA modulus
    getcontext().prec = k # set precision of decimals
    ctext = make_ctext()
    two = RSA_encrypt(2, e46, N46)
    lower = Decimal(0)
    upper = Decimal(N46)
    for _ in xrange(k):
        pivot = (lower + upper) / 2
        if RSA_parity(ctext):
            upper = pivot # result even; in lower half
        else:
            lower = pivot # result odd; in upper half
        ctext = (ctext * two) % N46
    ptext = num_convert(int(upper))
    print 'Recovered message: ' + ptext
    print 'Actual message: ' + message46.decode('base64')


# for challnge 47: Simple Bleichenbacher PKCS1.5 padding oracle



# for challenge 48: Complete Bleichenbacher PKCS1.5 padding oracle
