# Challenge description

> I heard calculators are a neat project so I made one for one of my classes. It is super secure and definitely bug free. Take a look and let me know what you think! I'm overflowing with excitement to hear how it stacks up against other calculators.

## Solution

### Initial analysis

The first thing I did was run `file` on the binary we were provided:

```bash
$ file ./stackulator
stackulator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c3cc52d59e76b48da3c7a89c7375b445d7d6aa3a, for GNU/Linux 3.2.0, not stripped
```

Yay, it's not stripped! That means function names will be preserved in Ghidra which is always nice :)

Here's the body of the `main` function for the `stackulator` binary according to Ghidra:

```c
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  long lVar3;
  undefined8 *puVar4;
  long in_FS_OFFSET;
  undefined8 local_88 [8];
  int local_48;
  undefined8 local_44;
  undefined8 local_3c;
  undefined8 local_30;
  undefined8 local_28;
  char local_20 [16];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puVar4 = local_88;
  for (lVar3 = 0xe; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_44 = 0x6c2e636c61632f2e;
  local_3c = 0x676f;
  puts("Welcome to my first calculator!\n\nWhat is your name?:");
  fgets((char *)local_88,99,stdin);
  printf("\nHello %s",local_88);
  if (local_48 == 1) {
    debug_menu(&local_44);
  }
  else {
    iVar1 = get_calc_args(&local_30,&local_28,local_20);
    if (iVar1 != 0) {
      uVar2 = 0xffffffff;
      goto LAB_0010174d;
    }
    perform_calc(local_30,local_28,(int)local_20[0]);
  }
  puts("\nGoodbye!");
  uVar2 = 0;
LAB_0010174d:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

Huh, the `debug_menu()` function sounds interesting. Let's take a look at that:

```c
void debug_menu(char *param_1)

{
  long in_FS_OFFSET;
  char local_40d;
  int local_40c;
  char local_408 [1016];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nDeveloper mode:\n**NOTE: remove this soon as logging has been disabled**\n");
  puts(
      "Select an option:\n1) Receive a compliment\n2) View log file\n3) Get a random YouTube link\n4 ) Show me an ASCII bee\n"
      );
  __isoc99_scanf(&DAT_001020c9,&local_40d);
  if (local_40d == '4') {
    printf("\n                      __    ");
    printf("\n                     // \\   ");
    printf("\n                     \\\\_/ //");
    printf("\n     -.._.-\'\'-.._.. -(||)(\')");
    puts("\n                     \'\'\'    ");
    goto code_r0x00101396;
  }
  if (local_40d < '5') {
    if (local_40d == '3') {
      puts("\nhttps://www.youtube.com/watch?v=dQw4w9WgXcQ");
      goto code_r0x00101396;
    }
    if (local_40d < '4') {
      if (local_40d == '1') {
        puts("\nYou are good at making secure calculators");
        goto code_r0x00101396;
      }
      if (local_40d == '2') {
        puts("\nLog contents:");
        local_40c = open(param_1,0);
        read(local_40c,local_408,1000);
        puts(local_408);
        goto code_r0x00101396;
      }
    }
  }
  puts("\nDisobedience saddens me. Goodbye.");
code_r0x00101396:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

[Huh, I wonder what that youtube link is?](https://www.youtube.com/watch?v=dQw4w9WgXcQ) ;)

Jokes aside though, reading the log contents sounds interesting since it reads a file. I initially assumed that we had to read the `calc.log` file\* but a) its only contents are `1 + 2 = 3` and b) we were told that the flag was actually located in the file `flag`. Based on the debug menu prompt, we'll have to input a 2 to get the log file to print. The path of the file that's read is passed as `param_1`, so we'll have to figure out how to change the path that's passed.

\*If you're wondering where I got `calc.log`, in the `main()` function `local_44` is assigned to the hex number `0x6c2e636c61632f2e`, which is actually the string `l.clac/.` (it's reversed due to how numbers are represented in memory; if you're curious, you can read about [endianness](https://chortle.ccsu.edu/assemblytutorial/Chapter-15/ass15_3.html)). I just assumed the `.log` file extension because that's what's normally used for logs :)

### Messing with memory

As I mentioned earlier, `local_44` is the path of the log file (or flag file in our case) that gets read in the debug menu. Unfortunately, whatever you type in is read to the variable `local_88`, not `local_44`, so you can't modify the path directly. Luckily for us though, everything is stored on the stack instead of the heap, so we can modify more memory than just our name. The reason is because of two different lines in `main`:

```c
undefined8 local_88 [8]; // line 10

fgets((char *)local_88,99,stdin); // line 28
```

`local_88` is declared to be an array 8 characters (the `[8]` part after its name), but up to 99 (well, 98 and a null byte; more on that later) characters are read in the `fgets` call on line 28, meaning that we can actually assign to memory past the end of the `local_88` array.

As an aside, one thing I realized during this challenge is that the `local_*` variable names in Ghidra actually indicate offsets from the stack pointer, where a higher number after `local_` indicates a position further up on the stack (and lower in memory by convention, for some reason).

Anyways, in order to actually get to the debug menu in the first place, the value of the `int` variable `local_48` has to be 1. That means that with our carefully crafted input, we have to overwrite the values of both `local_48` (debug menu check) and `local_44` ("log" file path). Going off of the stack offset suffixes on the `local_` variables, the user input (`local_88`) is read to the address `$rsp - 0x88` ($rsp is the stack pointer) and the debug check integer is located at `$rsp - 0x48`. Taking the difference between these addresses, there are 64 bytes between the user's input and the debug menu check that we have to fill with something. I opted for 64 `b`s, but you could choose any (ASCII/single-byte) character (that means no emojis ;)) or the beginning of the [`Wikipedia page about buffer overflows`](https://en.wikipedia.org/wiki/Buffer_overflow).

`int`s by default span 4 bytes in memory (I think it's technically implementation-dependent but that doesn't matter in this case), so the next 4 bytes of our payload have to represent the number 1 across those 4 bytes. If you read the link about endianness from above you'll know what I'm going to say next, but if you didn't there are two ways integers are represented in memory. The bytes making up the integer can either be ordered by increasing significance/higher value (this is called "little endian") or by decreasing significance/lower value ("big endian;" this is more akin to how we write numbers). Way back when I ran the `file` command, the output mentioned that `stackulator` was an `LSB` executable, which indicates that integers are stored in little-endian fashion. This means that in memory, the (4-byte) integer 1 is represented as `0x01000000`. Unfortunately those characters aren't typeable on a keyboard, but `pwntools` has a convenience function `p32` (more information about it [here](https://docs.pwntools.com/en/latest/intro.html#packing-integers)) that generates that byte sequence for us. The `32` represents the number of bits in the output, which in this case is 32 (4 bytes * 8 bits/byte -> 32 bits).

After all of that, we still have to modify the log file path to read the `flag` file. Luckily the path string on the stack is located right after the debug check integer, so we don't have to add any additional padding. It might be tempting to just append `./flag` to our current payload, but that wouldn't actually work since we'd end up with the path `./flag.log` (at least I think) since we don't overrwrite the end of the original path. In order to make the path just `./flag`, we need to append a null byte (`\x00` or `\0` in Python) to our payload. If you remember from earlier, I mentioned that `fgets` reads up to a number of characters one less than its second argument. This is because all C strings are what's called "null-terminated," which means that then end with a null byte (`00000000`). We can abuse this fact to end the path string prematurely by also appending a null byte to our input, which disregards any memory that was part of the string beforehand.

To summarize all of that, our payload will consist of the following:

- 64 `b`s
- the 4 bytes `0x01000000` to represent the integer 1
- `./flag` and a null byte to end the string

Now all we should have to do is send that to the server :)

### Exploitation time

[This solve script](./solve.py) builds the payload mentioned above and handles the various prompts/etc. that the server prints out. After running it, you should get something similar to the following output (assuming you have `pwntools` installed, that is):

```shell
$ python stackulator_solve.py
[+] Opening connection to chal.ctf-league.osusec.org on port 7184: Done
Welcome to my first calculator!

What is your name?:

Hello bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Developer mode:
**NOTE: remove this soon as logging has been disabled**

Select an option:
1) Receive a compliment
2) View log file
3) Get a random YouTube link
4) Show me an ASCII bee



Log contents:
osu{m4y83_1_5h0u1d_571ck_w17h_4_71}


Goodbye!

[*] Closed connection to chal.ctf-league.osusec.org port 7184
```

And there's our flag: `osu{m4y83_1_5h0u1d_571ck_w17h_4_71}`. Not sure why you'd include a developer mode in a calculator, but if you're gonna write it like this then yeah, maybe you should stick to a good old TI :)
