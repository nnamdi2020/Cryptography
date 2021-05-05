#!/usr/bin/env python

#Cryptography Project 3 - AES
# Nnamdi Osuagwu 

import sys

# S-Box
sBox = [0x1, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]


w = [None] * 6




def intToVec(n):
    #Convert a 2-byte integer into a 4-element vector
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]


def mult(p1, p2):
    #Multiply two polynomials in GF(2^4)/x^4 + x + 1
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111


def vecToInt(y):
    #Convert a 4-element vector into 2-byte integer
    return (y[0] << 12) + (y[2] << 8) + (y[1] << 4) + y[3]


def addKey(s1, s2):
    #Add two keys in GF(2^4)
    return [i ^ j for i, j in zip(s1, s2)]


def sub4NibList(sbox, s):
    #Nibble substitution function
    return [sbox[e] for e in s]


def shiftRow(s):
    #ShiftRow function
    return [s[0], s[1], s[3], s[2]]


def keyExp(key):
    #Generate the three round keys
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)

    Rcon1, Rcon2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]


def encrypt(ptext):
    #Encrypt plaintext block
    def mixCol(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]

    current_state = intToVec(((w[0] << 8) + w[1]) ^ ptext)
    current_state = mixCol(shiftRow(sub4NibList(sBox, current_state)))
    current_state = addKey(intToVec((w[2] << 8) + w[3]), current_state)
    current_state = shiftRow(sub4NibList(sBox, current_state))
    return vecToInt(addKey(intToVec((w[4] << 8) + w[5]), current_state))


def decrypt(ctext):
    #Decrypt ciphertext block
    def iMixCol(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]

    current_state = intToVec(((w[4] << 8) + w[5]) ^ ctext)
    current_state = sub4NibList(sBoxI, shiftRow(current_state))
    current_state = iMixCol(addKey(intToVec((w[2] << 8) + w[3]), current_state))
    current_state = sub4NibList(sBoxI, shiftRow(current_state))
    return vecToInt(addKey(intToVec((w[0] << 8) + w[1]), current_state))


def getBin(x, n):
    return format(x, 'b').zfill(n)
    """Python string method zfill() pads string on the 
     left with zeros to fill width."""


if __name__ == '__main__':

    print('This program encrypts a Fixed Binary Plaintext using Advanced Encryption Standard (AES)')
    print('\n')

    """ Base 2 Format: 0b - In Binary we count in base two, 
    where each place can hold one of two values: 0 or 1."""
    plaintext = 0b0110111101101011
    key = 0b1010011100111011
    ciphertext = 0b0000011100111000
    keyExp(key)
    textValue = getBin(plaintext, 16)
    cipher = getBin(encrypt(plaintext), 16)
    plain = getBin(decrypt(ciphertext), 16)

    print('Binary Plaintext: ', textValue)
    print('Binary Ciphertext: ', cipher)
    print('Binary Decrypted text: ', plain)
    print('\n')