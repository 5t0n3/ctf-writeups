#!/usr/bin/python3
from os import urandom
from base64 import b64encode
from flag import FLAG
MAX_LENGTH = 60

# performs an XOR in the two byte objects and returns the result
def xor_bytes(b1:bytes, b2:bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

# xor all byte objects in a list with eachother
def xor_list(bytes_list) -> bytes:
    result = bytes_list[0]

    for b in bytes_list[1:]:
        result = xor_bytes(result, b)
    
    return result


if __name__ == '__main__':
    # get 3 one time pads
    otps = [urandom(MAX_LENGTH) for _ in range(3)]

    # combine the one time pads into a "super" one time pad
    super_otp = xor_list(otps)

    # encrypt the flag using the super one time pad
    enc_flag = xor_bytes(FLAG.encode(), super_otp)
    
    # print out the encrypted flag
    print(f'The encrypted flag in base 64:')
    print(b64encode(enc_flag).decode())

    for otp in otps:
        # get the message that the user wants to encrypt (up to 60 characters)
        print('Enter message you would like to encrypt (input truncated to 60 characters): ')
        user_message = str(input())[:60]

        # encrypt the message using xor
        enc_message = xor_bytes(user_message.encode(), otp)

        # print encrypted message
        print(f'Your encrypted message is in base 64:')
        print(b64encode(enc_message).decode())