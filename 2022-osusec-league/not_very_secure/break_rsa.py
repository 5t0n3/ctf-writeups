from sympy import nextprime

from base64 import b64decode
import math


N = 4777805290463711026025530760997341215210485822996023118027623646117723191500719041518959799725566059428554801696706296582581695310479723757513175744877550944865803932093280029829366260565558093216826465112625300559200066643691564027696443851265545121928906737207782768662058439770013206909817779391660295937449587329571897991774335797160269734366923630381643014686236264025697244867112514868261836050971328293396853758777800827880833925181379721342353017797906724353979687889041742404605317986943822242304998601391883361325971913770331586178253989604353973935125868269417765045588838194560248401591031608094124211
E = 11
FLAG_BASE64 = "SOIBDfTgLGiKSogVGF1ell/EJNthxiL+rP7QjMjg4j4l58piOWEnF7oDQMAc3y3QhXHBC4RU4TsemCENzTae1zpBJ5W3XmwbBvF8ot19E28FVBjZLE5uUk7caH8b1q/2GhZQnLNtfHHHZzlFcvg5ENiA1iqlpxoO+VLcgLqs2zpDFihamaGLOA0I1yC/vwtn79rgg3UMJVikFqlrBMdN2h3WuMKwPB9vCfjXI+XrhPDRr96rO5xKVPzQvjJSu4Rz3jsKbz0WmnNE7lmNSZDi+P+KKBFZffJWKRaIwEWJQl8y/4yFjz1rHhX/ta2mPVEEBfO8sM/oc3UPp8E2BKAB"

# check if any of the next 15 primes evenly divide n
p = math.isqrt(N)
for _ in range(15):
    p = nextprime(p)
    if N % p == 0:
        break

# p * q = n -> q = n / p
# note that the double slash is integer division (as opposed to floating point division)
q = N // p

print(f"p = {p}")
print(f"q = {q}")
print(f"factors match n: {p * q == N}")

# find the decryption exponent
phi = (p - 1) * (q - 1)
d = pow(E, -1, phi)

# decode & decrypt the data by just doing the encryption in reverse
decoded_data = b64decode(FLAG_BASE64)
dataInt = int.from_bytes(decoded_data, byteorder="little")
decrypted = pow(dataInt, d, N)
flag = decrypted.to_bytes(decrypted.bit_length() // 8 + 1, "little")

print()
print("Flag: " + flag.decode())
