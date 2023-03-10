# secret_message

> A secret message has been sent to you through this image, can you demonstrate your 'hackerman' skills and find the flag?

Provided: [hackerman.jpg](hackerman.jpg)

## Solution

Let's take a look at the image itself:

<div align="center">
<img src="hackerman.jpg" alt="Hackerman image in vaporave style">
</div>

The image itself looks normal, but running [`binwalk`](https://github.com/ReFirmLabs/binwalk) on it tells a different story:

```shell
$ binwalk hackerman.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, big-endian, offset of first image directory: 8
378176        0x5C540         Zip archive data, encrypted at least v2.0 to extract, compressed size: 343, uncompressed size: 625, name: enc.py
378599        0x5C6E7         Zip archive data, encrypted at least v1.0 to extract, compressed size: 37, uncompressed size: 25, name: flag.enc
378872        0x5C7F8         End of Zip archive, footer length: 22
```

So along with the normal image data, there appears to be an encrypted zip archive added on to the end of this image containing two files: flag.enc and enc.py.
We're not given any information about what the password for that zip archive could be, though, so what else to do than poke around a hexdump of the provided image?

You could use something like [hexed.it](https://hexed.it/) to look at the hexdump of hackerman.jpg, but I ended up just using Vim since it can actually natively generate hexdumps of files by opening them up and running `:%!xxd`.
After poking around for a bit, I eventually noticed this section of the hexdump right around the beginning of the encrypted zip data from above:

```
0005c520: 4730 2674 f92c c8fb f7ef ffd9 7333 7459  G0&t.,......s3tY
0005c530: 385f 4331 6734 6d3d 6472 6f77 7373 6170  8_C1g4m=drowssap
0005c540: 504b 0304 1400 0900 0800 c694 6656 1183  PK..........fV..
0005c550: b5f8 5701 0000 7102 0000 0600 1c00 656e  ..W...q.......en
0005c560: 632e 7079 5554 0900 0394 a306 64ea a306  c.pyUT......d...
```

Based on good old [Wikipedia](https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure), JPEG images all end with the bytes `ff d9`, which you can see towards the end of the first row above.
All zip archives also begin with `PK` (`50 4b` in hex) again based on [Wikipedia](https://en.wikipedia.org/wiki/ZIP_(file_format)).
Between those end and start bytes, though, there's this weird string that seems out of place: `s3tY8_C1g4m=drowssap`.
It took an embarrasingly long time for my team to realize that it was actually a reversed string, which when unreversed becomes `password=m4g1C_8Yt3s` which is definitely useful in our case :)

Unzipping the image itself seems to skip all the JPEG/TIFF data, so we can just do that and enter our password that we just found:

```shell
# the -P flag allows us to provide the password as part of the command rather than typing it later
$ unzip -P m4g1C_8Yt3s hackerman.jpg
Archive:  hackerman.jpg
warning [hackerman.jpg]:  378176 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  inflating: enc.py
 extracting: flag.enc
```

Let's check out the contents of [`enc.py`](unzipped/enc.py):

```python
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
```

Based on that, it looks like `flag.enc` just has the flag xored with some bytes at a specific offset in the `hackerman.jpg` file.
Since the zip archive and password were just appended to it in our case, that offset remains the same, so we can turn this into a [decryption script](decrypt_flag.py) with relatively few modifications :)

```python
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
```

Running it does indeed give us our flag :)

```shell
$ python decrypt_flag.py
flag: osu{1ook_for_m@9ic_8yTe5}
```

And there it is! `osu{1ook_for_m@9ic_8yTe5}`.
I guess magic bytes really did prove useful in this challenge, even if it took my team forever to figure out we needed to reverse a string :)