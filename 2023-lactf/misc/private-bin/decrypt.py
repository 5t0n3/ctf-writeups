from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from base64 import b64decode
import json

KEY = b"3cVSg0HRNq8SmAezph2ZBDl6B4WeEcAg"


def decrypt_file(file_entry):
    global KEY

    def decrypt(data):
        data = b64decode(data)
        iv, real_data = data[:16], data[16:]

        decryptor = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
        decrypted = decryptor.update(real_data) + decryptor.finalize()

        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(decrypted) + unpadder.finalize()

        return unpadded

    filename = decrypt(file_entry["name"]).decode()
    typ = decrypt(file_entry["type"]).decode()
    content = decrypt(file_entry["content"])

    print(f"Writing {filename} (type: {typ})")
    with open(filename, "wb") as out:
        out.write(content)


if __name__ == "__main__":
    with open("pcap-contents/1cca80be-1b8a-4837-bdb1-cb56199e6cd7.json", "r") as f:
        paste_json = json.load(f)

    for file in paste_json["files"]:
        decrypt_file(file)
