#!/usr/bin/env python3
from os import remove
from os.path import exists

OFFSET = 456

# open the flag.txt file and read the contents as bytes
with open('flag.txt', 'rb') as f:
    flag = f.read()

# open the benny.gif file as bytes and get a one time pad from within the file
with open('hackerman.jpg', 'rb') as f:
    gif_otp = f.read()[OFFSET:OFFSET+len(flag)]

# encrypt the flag using xor
enc_flag = bytes(b1 ^ b2 for b1, b2 in zip(gif_otp, flag))

# save the encrypted flag to file 
with open('flag.enc', 'wb') as f:
    f.write(enc_flag)

# delete the original flag file
if exists('flag.txt'):
    remove('flag.txt')

