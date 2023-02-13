from base64 import b64decode, b64encode
from urllib.parse import unquote_plus, quote_plus

def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))

auth = "mQQGDoGKo3Y0nVA2Uyz3ug%3D%3D.7PUFAYWIcbbZ2hnVSMpDAw%3D%3D.tBQr%2FSqwhT1hg%2BDzri2airPQuSmlA68ow61lwVa1blHkMWsMJUqxzogUdvJbjioXfYZJ2HBU5k%2BU4vju%2Bn8%3D"

if __name__ == "__main__":
    iv, tag, ct = auth.split(".")
    ct = b64decode(unquote_plus(ct))
    new_ct = xor(b'{"tmpfile":"/flag.txt"}', xor(b'{"tmpfile":"/tmp/pastestore/', ct))
    new_ct = quote_plus(b64encode(new_ct))
    
    print(f"new cookie: {iv}.{tag}.{new_ct}")
