# crypto/guess-the-bit! (222 solves/341 points)

> I'm trying out for this new game show, but it doesn't seem that hard since there are only two choices? Regardless, I heard someone name Pollard could help me out with it?

Provided [`chall.py`](chall.py)

## Solution

The challenge code isn't too long for this one, so I'll include the relevant part here:

```python
a = 6

# --snip--

for i in range(150):
    bit = random.randrange(0,2)
    c = random.randrange(0, n)
    c = c**2
    if bit == 1:
        c *= a
    print("c = ", c)
    guess = int(input("What is your guess? "))
    if guess != bit:
        print("Better luck next time!")
        exit()


print("Congrats! Here's your flag: ")
flag = open("flag.txt", "r").readline().strip()
print(flag)
```

Based on that, in order to get the flag we have to guess the bit correctly 150 times in a row (hence the name of this challenge).
Because `c` is squared before multiplying it by `a` (or not, depending on the random bit), all of its factors have to appear twice in the `c` that we're given except for potentially 6 if the bit is one.
My first thought, then, was checking whether `c` was divisible by 6 exactly twice (i.e. the original `c` had a factor of 6, so c^2 has two 6 factors).
The relevant portion of my solve script ended up looking like this:

```python
    for i in range(150):
        print(f"guess {i+1}")
        conn.recvuntil(b"c =  ")
        c = int(conn.recvline())

        if c % pow(6, 2) == 0 and c % pow(6, 3) != 0:
            bit = 0
        elif c % 6 == 0:
            bit = 1
        else:
            bit = 0

        conn.sendlineafter(b"guess? ", str(bit).encode())
```

I got lucky and only had to run that twice in order to get the flag initially, but that naive approach is more cheese than anything :)
Eventually I realized that I should instead be checking the number of times `c` (well c^2 potentially multiplied by a) was divisible by 6, since an even number would mean the bit was 0 (no `a` multiplication) while an odd number would make it 1 (multiplied by `a`).
This approach properly handles potentially having 6 as a factor more than 3 times over the naive approach, meaning that you don't have to run it multiple times if you get unlucky :)

Here's what [that solve script](bits_guessed.py) ended up looking like:

```python
from pwn import *


if __name__ == "__main__":
    context.log_level = "error"
    conn = remote("lac.tf", 31190)

    max_six_factors = 0

    print("Guessing bits...")
    print()
    for i in range(150):
        conn.recvuntil(b"c =  ")
        c = int(conn.recvline())

        # check multiplicity of 6 as a factor
        divisions = 0
        while c % 6 == 0:
            c //= 6
            divisions += 1

        # odd divisions -> multiplied by a, even -> not multiplied
        bit = divisions % 2
        conn.sendlineafter(b"guess? ", str(bit).encode())

        # curiosity :)
        max_six_factors = max(max_six_factors, divisions)

    print(conn.recvuntil(b"}").decode())
    print()
    print(f"Maximum number of 6 factors: {max_six_factors}")
```

And here's the result of running it:

```shell
$ python bits_guessed.py
Guessing bits...

Congrats! Here's your flag:
lactf{sm4ll_pla1nt3xt_sp4ac3s_ar3n't_al4ways_e4sy}

Maximum number of 6 factors: 5
```

And there's our flag!
The maximum multiplicity of 6 as a factor was 5 in that run, which explains why the naive approach didn't work 100% of the time.
I guess that would render the naive approach similar to most game shows but hey, if there's an easy button why not push it? :)
