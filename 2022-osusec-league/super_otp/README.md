# super_otp

## Challenge description

> One time pads are a way of encrypting a message in a way that cannot be cracked. I have developed the Super One Time Pad to increase its security!
> Good Luck trying to find the flag!

## Solution

### What [`super_otp.py`](./provided/super_otp.py) does

In order to encrypt the flag, the program running on the server generates 3 random 60-byte bytestrings and XORs them together to create what the code refers to as a "super OTP." This key is then XORed with the flag bytestring, encoded into Base64, and sent when you connect to the server. You are then allowed to input 3 messages that are truncated to 60 characters (well, bytes) with each one being XORed with one of the three OTPs that make up the super OTP.

### The XOR operation

One of the really useful properties of the XOR operation is that it is its own inverse. That is, if you have two bytestrings A and B, A ⊕ B ⊕ B is equivalent to A (⊕ is the symbol for XOR). This can be proven in a couple ways, but the most relevant one is that XORing a bytestring with itself will yield a bytestring of all zeroes, since there will either be two 0s or two 1s in each position. It then follows that XORing a bytestring with one made of only zeroes will yield the original bytestring: A ⊕ 000... -> A. We can take advantage of this by sending in a bunch of null bytes (i.e. bytes that contail only zeroes) as messages to the server, which will then give us back the OTPs directly. Note that this is not the same as sending 60 `0` characters: the null character has an ASCII codepoint of 0 (decimal), while the character `0` has a codepoint of 48 (if you're curious you can find a full ASCII table [here](https://www.asciitable.com/)). This actually tripped me up when writing my solving program, so that's something to keep in mind in the future :)

Using a null bytestring also eliminates an extra step of XORing what you get from the server with the original message, so that's less code for me to write ;)

### Obtaining the super OTP

Because you can't type null bytes on any keyboard (that I know of, at least), I decided to use pwntools to write a Python program to fetch the flag for me. I spent a while (way too long) trying to figure out the order of prompts vs. the OTPs being sent but eventually figured it out. As an aside, while I was initially sending just 60 null bytes as each message to get the three OTPs, I eventually realized that you only need as many as are in the Base64-decoded flag string, which ended up being less than 60. It would work equally well with 60 due to how the `xor_bytes` function works (namely the `zip()` call), but I just decided to do it this way because less memory usage or something :)

As a consequence of how `pwntools`'s `remote.readline()` function works, I also had to strip off the newline characters from the OTPs received from the server before decoding them from Base64. After I got all of that working in [this script](./otp_crack.py), all I had to do was XOR the three OTPs together and XOR the super OTP with the encrypted flag to get the flag in plaintext: `osu{nev3r_R3uSE_On3_7iM3_P@D$}`. Funny how the flag didn't follow its own advice :)
