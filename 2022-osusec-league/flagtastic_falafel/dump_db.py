import base64

FILENAME = "./orders-base64"

with open(FILENAME, "r") as encoded:
    contents_bin = base64.b64decode(encoded.read())

with open("orders.db", "wb") as db:
    db.write(contents_bin)
