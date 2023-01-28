from qrcodegen import QrCode
filename = input("Enter fname to qr: ")
data = open(filename,'rb').read()
print(data)
a = QrCode.encode_binary(data, QrCode.Ecc.LOW)
def print_qr(qrcode: QrCode) -> None:
    # Taken from packaged examples of QR gen
    border = 2
    for y in range(-border, qrcode.get_size() + border):
        for x in range(-border, qrcode.get_size() + border):
            print("\u2588 "[1 if qrcode.get_module(x,y) else 0] * 2, end="")
        print()
    print()

def createPBM(qrcode):
    out = open(filename+'.qr.pbm','w')
    border = 2
    out.write('P1\n')
    out.write(str(qrcode.get_size()+2*border) + ' ')
    out.write(str(qrcode.get_size()+2*border) + '\n')
    for y in range(-border, qrcode.get_size() + border):
        for x in range(-border, qrcode.get_size() + border):
            out.write('1' if qrcode.get_module(x,y) else '0' + ' ')
        out.write('\n')
    out.close()


print_qr(a)

createPBM(a)
