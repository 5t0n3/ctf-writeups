import requests
from sympy import primefactors
from sympy.ntheory.modular import crt

from hashlib import sha256
import hmac

# taken from key_exchange.py
key = {
    "0": 0,
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    "6": 6,
    "a": 70,
    "b": 71,
    "c": 72,
    "d": 73,
    "e": 74,
    "f": 75,
    "g": 76,
    "h": 77,
    "i": 78,
    "j": 79,
    "k": 80,
    "l": 81,
    "m": 82,
    "n": 83,
    "o": 84,
    "p": 85,
    "q": 86,
    "r": 87,
    "s": 88,
    "t": 89,
    "u": 90,
    "v": 91,
    "w": 92,
    "x": 93,
    "y": 94,
    "z": 95,
    "_": 96,
    "{": 97,
    "}": 98,
    "!": 99,
}


# modified to not encode the result since I just decode it anyways
def long_to_str_flag(long_in):
    new_map = {v: k for k, v in key.items()}
    list_long_in = [int(x) for x in str(long_in)]
    str_out = ""
    i = 0
    while i < len(list_long_in):
        if list_long_in[i] < 7:
            str_out += new_map[list_long_in[i]]
        else:
            str_out += new_map[int(str(list_long_in[i]) + str(list_long_in[i + 1]))]
            i += 1
        i += 1
    return str_out


def get_mac(session, A):
    resp = session.get(f"https://down-under-tlejfksioa-ul.a.run.app/?A={A}").json()
    return int(resp["hmac"]).to_bytes(length=256 // 8, byteorder="big")


def test_mac(secret):
    secret_bytes = secret.to_bytes(length=(secret.bit_length() + 7) // 8, byteorder="big")
    mac = hmac.new(key=secret_bytes, msg=b"My totally secure message to Alice", digestmod=sha256)
    return mac.digest()


# we know that the flag exponent is even since it ends in }
moduli = [2]
residues = [0]

if __name__ == "__main__":
    # minimum number of residues found through testing
    while len(residues) < 10:
        # preserve session cookie :)
        s = requests.session()

        # get diffie-hellman generator & prime
        params = s.get("https://down-under-tlejfksioa-ul.a.run.app/?A=1").json()
        p = params["p"]
        g = params["g"]

        # get smallish factors (besides 2) of the order of ℤₚ*
        order_factors = primefactors(p - 1, limit=100000)[1:]
        print("Current iteration factors:", order_factors)

        for w in order_factors:
            print("Testing factor:", w)

            # choose a specific exponent to place the secret in a smaller subgroup of ℤₚ×
            # (see https://crypto.stackexchange.com/q/27584)
            k = (p - 1) // w
            A = pow(g, k, p)
            mac = get_mac(s, A)

            # brute force the HMAC with all possible remainders mod the current factor/subgroup order
            for i in range(w):
                s_cand = pow(A, i, p)
                if test_mac(s_cand) == mac:
                    print("Found remainder!", i)
                    moduli.append(w)
                    residues.append(i)
                    break

    # we do a little chinese remainder theorem
    flag_exp = crt(moduli, residues, check=False)[0]
    
    # sanity check (B = g^b mod p)
    assert pow(g, flag_exp, p) == params["B"]
    
    # flag :)
    print()
    print("Flag found!", long_to_str_flag(flag_exp))
