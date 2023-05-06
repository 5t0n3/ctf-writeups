if __name__ == "__main__":
    # encrypted hex data from provided zip
    data = bytes.fromhex("C9D4D2DCC592F7E7D29294FA92E9F5CA90E990C89497949293C8FA9296EA94FAC0D59090FA9690C5D2D59294FCDA")
    flag = ""

    for byte in data:
        # first and third most significant bits are flipped (BIT_5 and BIT_7 in schematic)
        byte ^= 0b10100000

        # least significant bits are xored with most significant bits
        byte ^= byte >> 4

        # convert codepoint back to character
        flag += chr(byte)

    print(flag)
