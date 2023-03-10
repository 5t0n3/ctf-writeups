OFFSET = 456

# open and read the encrypted flag file
with open('flag.enc', 'rb') as f:
    flag_enc = f.read()

# open the hackerman.jpg file and get the one time pad from the correct offset within the file
with open('hackerman.jpg', 'rb') as f:
    gif_otp = f.read()[OFFSET:OFFSET+len(flag_enc)]

# decrypt the flag using xor
flag = bytes(b1 ^ b2 for b1, b2 in zip(gif_otp, flag_enc))

# print out the decrypted flag :)
print("flag:", flag.decode())