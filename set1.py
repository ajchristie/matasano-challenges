#!/usr/bin/env python2
from collections import Counter

# for challenge 1: convert hex to base64
def hexToB64(h):
    return h.decode('hex').encode('base64')

# for challenge 2: return XOR of two fixed length strings
def fXOR(s1, s2):
    if len(s1) != len(s2):
        print 'Give me equal length buffers!'
        return None
    b1 = int(s1, 16)
    b2 = int(s2, 16)
    result = b1 ^ b2
    return format(result, 'x')

# for challenge 3: break a caesar cipher
def basicScore(c): # returns proportion of ascii characters in array c (sufficient here)
    filtered = filter(lambda x: 'a' <= x <= 'z' or 'A' <= x <= 'Z' or x == ' ', c)
    return float(len(filtered)) / len(c)

# N.B. a middle ground between these two would be to score each decryption against occurrences of just ETAOIN SHRDLU, which might help with multiple samples tying for the best freqScore.

def freqScore(c): # returns total deviation from english letter frequencies in array c
    freqs = [('a', 8.167), ('b', 1.492), ('c', 2.782), ('d', 4.253), ('e', 12.702), ('f', 2.228),
             ('g', 2.015), ('h', 6.094), ('i', 6.966), ('j', 0.153), ('k', 0.772),
             ('l', 4.025), ('m', 2.406), ('n', 6.749), ('o', 7.507), ('p', 1.929), ('q', 0.095),
             ('r', 5.987), ('s', 6.327), ('t', 9.056), ('u', 2.758), ('v', 0.978), ('w', 2.36),
             ('x', 0.15), ('y', 1.974), ('z', 0.074)]
    filtered = filter(lambda x: 'a' <= x <= 'z' or 'A' <= x <= 'Z', c)
    l = len(c)
    filtered = ''.join(filtered).lower()
    counts = Counter(filtered)
    delta = 0
    for ch in freqs:
        delta += abs((float(counts[ch[0]]) / l) - ch[1])
    return delta # would it be better to normalize this somehow?

def deCaesar(s):
    hex_decoded = s.decode('hex')
    results = []
    for i in xrange(1, 255):
        xord = [chr(ord(c) ^ i) for c in hex_decoded]
        results.append([freqScore(xord), ''.join(xord), chr(i)])
    results.sort(key=lambda x: x[0], reverse=False)
    ## do the extra sorting for troubleshooting purposes; can return ranked list instead of just max
    return results[0]

# for challenge 4: detect a Caesared ciphertext
def findCaesar(l):
    results = []
    for ct in l:
        hex_decoded = ct.decode('hex')
        for i in xrange(1, 255):
            xord = [chr(ord(c) ^ i) for c in hex_decoded]
            results.append([freqScore(xord), basicScore(xord), ''.join(xord), chr(i)])
    results.sort(key=lambda x: x[0], reverse=False)
    results.sort(key=lambda x: x[1], reverse=True)
    # N.B. the basic sort is the better detector for this challenge
    return results[0]

# for challenge 5: Implement Vigenere cipher
def vigenere(p, k): # we'll assume everything's coming in ascii for this
    keylength = len(k)
    ciphertext = []
    for i, letter in enumerate(p):
        ciphertext.append(chr(ord(letter) ^ ord(k[i % keylength])))
    return ''.join(ciphertext).encode('hex')

# for exercise 6: Break Vigenere
def hammingDistance(b1, b2):
    return sum(bin(i ^ j).count('1') for i, j in zip(b1, b2))

def makeSegments(a, n):
    num_segs = len(a) / n
    segs = []
    for i in xrange(0, num_segs*n, n):
        segs.append(a[i:i+n])
    return segs

from itertools import combinations

def findKeyLength(ctextbytes):
    min_index = 100
    guess = 40
    #results = []
    for keylength in xrange(2, 41):
        segs = makeSegments(ctextbytes, keylength)
        round_min = 100
        for ind in combinations(range(len(segs)), r=2):
            index = float(hammingDistance(segs[ind[0]], segs[ind[1]])) / keylength
            if index == 0.0:
                break # too good to be true
            elif index < round_min:
                round_min = index
        else: # accept results only if index stayed positive
            if round_min <= min_index:
                min_index = round_min
                guess = keylength
        #results.append([keylength, min_index]) # for troubleshooting
    return guess

def breakCaesar(ctbytes): # differs from version above in assuming input is a bytearray
    results = []
    for i in xrange(1, 255):
        xord = [chr(c ^ i) for c in ctbytes]
        results.append([freqScore(xord), basicScore(xord), ''.join(xord), chr(i)])
    results.sort(key=lambda x: x[0], reverse=False)
    results.sort(key=lambda x: x[1], reverse=True)
    return results[0]

def breakVig(ctbytes):
    l = findKeyLength(ctbytes)
    num_blocks = len(ctbytes) / l
    pad_length = (l - (len(ctbytes) % l)) % l
    for _ in xrange(pad_length):
        ctbytes.append(4)
    rows = makeSegments(ctbytes, l)
    columns = zip(*rows)
    columns = [bytearray(col) for col in columns]
    shifts = []
    decryption = []
    for col in columns:
        _, _, dec, shift = breakCaesar(col)
        decryption.append(dec) # string
        shifts.append(shift)
    key = ''.join(shifts)
    rows = zip(*decryption)
    ptext = ''.join([''.join(row) for row in rows])
    return key, ptext[:len(ctbytes)]

def loadCT():
    with open('6.txt', 'r') as f:
        data = f.readlines()
    data = [line.strip() for line in data]
    ctext = ''.join(data)
    dctext = ctext.decode('base64')
    return bytearray(dctext)

# for challenge 7: AES-ECB
from Crypto.Cipher import AES

def AES128ECB(ctext):
    ciphertext = ctext.decode('base64')
    dcrypt = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)
    print dcrypt.decrypt(ciphertext)

# for challenge 8: detect AES-ECB
from collections import Counter

def catch128ECB(ctexts):
    results = []
    for ctext in ctexts:
        segs = makeSegments(ctext, 16)
        ctr = Counter(segs)
        results.append([ctext, ctr.most_common(1)])
    results.sort(key=lambda x: x[1], reverse=True)
    return results[0]
