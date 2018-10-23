#!/usr/bin/env python2
import random
import hashlib


# for challenge 33: Implement Diffie-Hellman
# parameters:
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
# 1536 bits
g = 2

def mod_exp(base, exp, mod):
    """ This is equivalent to pow but, in the spirit of the exercise..."""
    result = 1
    base %= mod
    while exp > 0:
        if (y & 1) == 1:
            result = (result * base) % mod
        y /= 2
        result = (base * base) % mod
    return result

def generate_keys(base, modulus):
    """
    Returns a public/private Diffie Hellman key pair given base and modulus parameters.
    Keys are returned as integers.
    """
    private = random.SystemRandom.randint(2, p) # this isn't appropriate, maybe, but for now...
    public = mod_exp(2, private)
    return public, private

def make_session_key(private, recieved):
    """
    Returns Diffie Hellman shared secret given user private key and recieved public key as
    integers.
    """
    return mod_exp(recieved, private)

def derive_keys(session_key):
    """
    Given session key (integer), returns a pair of 128-bit keys formatted as hex strings.
    """
    sha = hashlib.sha256()
    sha.update('{:x}'.format(session_key))
    digest = sha.hexdigest()
    return digest[:32], digest[32:]

def derive_key(session_key):
    """
    Like above, but returns a single SHA-1-derived key from the passed (integer) session key.
    """
    sha = hashlib.sha1()
    sha.update('{:x}'.format(session_key))
    return sha.hexdigest()


# for challenge 34: Implement MITM key fixing
# this is really almost only fun, or ore enlightening, if you actually do the networking part.
# Later.


# for challange 35: Implement DH group negotiation and break with mailcious 'g'



# for challange 36: Implement Secure Remote Password



# for challange 37: Break SRP with zero key



# for challenge 38: Offline dictionary attack on SRP



# for challenge 39: Implement RSA



# for challenge 40: Implement RSA e=3 broadcast attack
