# hill-easy (75 solves/459 points)

> I found a cool rock. Help me figure out what it says.

Provided: [`chall.py`](chall.py)

## Solution

Before we do anything, let's try interacting with the challenge server:

```shell
$ nc lac.tf 31140
On the hill lies a stone. It reads:
H(Qi!kKBM{ BbEt3s/2]
)na\|YO4hNb7fXO>QVC]

A mysterious figure offers you 10 attempts at decoding the stone:

Enter your guess: A
Your guess must be exactly 40 characters.

Enter your guess: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Incorrect:
KYjcZ80[RxHeG8i[1wm=
KYjcZ80[RxHeG8i[1wm=
You have 9 attempts left

Enter your guess: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
Incorrect:
KYjcZ80[RxHeG8i[1wm=
IP;CX/mksh!LFR<;* 44
You have 8 attempts left

Enter your guess:
```

Hmm, so it looks like we're provided a couple things right off the bat, and we're given two things based on each guess we supply this "mysterious figure?"
Since sending all `A`s led to both of the resulting keyboard mashes being the same but changing the last letter to a B changed the second one, we can probably assume that our guess is being split in half.

Checking out [the provided program](chall.py) confirms this:

```python
n = 20
A = np.random.randint(0, 95, [n, n])

fakeflag = "lactf{" + ''.join([chr(ord('a')+np.random.randint(0,26)) for _ in range(33)]) + "}"
fakeflag2 = "lactf{" + ''.join([chr(ord('a')+np.random.randint(0,26)) for _ in range(33)]) + "}"
assert(len(fakeflag) == 2*n)
assert(len(fakeflag2) == 2*n)
f1 = encrypt(fakeflag[:n])
f2 = encrypt(fakeflag[n:])
f3 = encrypt(fakeflag2[:n])
f4 = encrypt(fakeflag2[n:])

# --snip--

def encrypt(s):
    return vtos(np.matmul(A, stov(s))%95)

# --snip part 2--

def oracle(guess):
    o1 = encrypt(guess[:n])
    o2 = encrypt(guess[n:])
    if o1 == f1 and o2 == f2:
        giveflag()
    print("Incorrect:")
    print(o1)
    print(o2)
```

So it looks like our input is split in half, and each half is then encrypted by multiplying it by this mysterious `A` matrix.
The two random strings we're given are actually `f1` and `f2`, so it looks like if we're able to decrypt those halves then we get the flag.
Later on in the program, though, there is another way to get the flag (comments are mine):

```python
print("On the hill lies a stone. It reads:")
# encrypted halves of first fake flag
print(f1)
print(f2)
print("\nA mysterious figure offers you 10 attempts at decoding the stone:")
for i in range(10):
    # guess calls the oracle() function from earlier, which encrypts input after validating it
    guess(i)
# second chance :)
print("\nThe figure frowns, and turns to leave. In desperation, you beg for one more chance. The figure ponders, then reluctantly agrees to offer you an alternative task.")
print("Create a new stone that decodes to the following:")
print(fakeflag2)
guess1 = input("\nEnter the first half: ")
guess2 = input("\nEnter the second half: ")
if guess1 == f3 and guess2 == f4: # f3/f4 are the encrypted halves of fakeflag2
    giveflag()
else:
    print("Nope.")
```

So if we're not able to guess the two halves of the first fake flag in our 10 guesses, we need to figure out a way to encrypt the second fake flag in order to get the real one.
Really the only way to do this is to recover the random `A` matrix, which as it turns out isn't actually too bad :)
I'll go over two ways to do this: the cursed way I used initially and the one I realized would work later while solving [crypto/hill-hard](../hill-hard) (lol).

### The cursed way

Because we're given 10 queries to encrypt the two halves of whatever string/vector we send in, we effectively have 20 encryption oracle queries, which just so happens to be the number of rows/columns in the $\mathbf{A}$ matrix.
Having just come from doing [crypto/vinaigrette](../../../2023-dicectf/vinaigrette) at DiceCTF last week, basically my first thought when solving this challenge was setting up a matrix equation of the form $\mathbf{A}\mathbf{X} = \mathbf{C}$, where $\mathbf{X}$ is a matrix containing random queries we send to the oracle as column vectors and $\mathbf{C}$ is the same but for the corresponding encrypted vectors.
Assuming our $\mathbf{X}$ matrix is invertible, it follows then that $\mathbf{A} = \mathbf{C}\mathbf{X}^{-1}$.
This directly gives us the $\mathbf{A}$ matrix which we can then use to encrypt arbitrary vectors, like the second fake flag we're given.

This method of recovering $\mathbf{A}$ is implemented in [`cursed_rock.sage`](cursed_rock.sage) if you want to check it out, and it does indeed give us the right flag:

```shell
$ sage cursed_rock.sage
Querying oracle...

The text on the stone begins to rearrange itself into another message:
lactf{tHeY_SaiD_l!NaLg_wOuLD_bE_fUN_115}
```

I guess this way isn't actually that cursed, but there is another way to recover the $\mathbf{A}$ matrix without requiring matrix invertibility :)

### The easy way

Like I mentioned earlier, I only realized this method existed when doing the harder version of this challenge.
The change that made me realize this was the banning of spaces in our oracle queries.
To see why spaces are useful, let's take a look at how the strings we send in are converted to vectors:

```python
def stov(s):
    return np.array([ord(c)-32 for c in s])
```

Nothing too complicated :)
Each character is just mapped to its ASCII codepoint minus 32, which also explains why everything is done mod 95: the server only accepts characters with codepoints in the range 32 to 126 inclusive, which maps to the interval 0 to 95 after subtracting 32.
As it turns out, the ASCII codepoint of the space character is exactly 32:

```python
>>> ord(" ")
32
```

This means that spaces get mapped to zeros in the `stov` function.
This is actually really convenient since it means we can effectively zero out columns of the $\mathbf{A}$ matrix during multiplication, allowing us to focus in on specific columns.
If we send in vectors of the form (1 0 0 ... 0 0)ᵀ, (0 1 0 ... 0 0)ᵀ, and so on, the results of the encryption/matrix multiplication process will just be the individual columns of $\mathbf{A}$, so when using this method we don't have to do any postprocessing of the responses we receive from the oracle except stick them into a matrix.
In order to get 1s in the resulting vectors, we have to send in exclamation points in the positions corresponding to the columns of $\mathbf{A}$ we want to recover:

```python
>>> chr(32 + 1)
'!'
```

When using this method, then, we just need to send the server two queries at a time (recall our 40-character query is split in half), each with one `!` character and the rest of the characters as spaces.
I've included my implementation of this as [`easy_rock.sage`](easy_rock.sage), which again gives us the real flag (as well as some other additional information about the fake flags :)):

```shell
$ sage easy_rock.sage
Querying oracle

Fake flag 1 (encrypted): 5TV^K#AR\{Qeq?a. Qslt E,/x1=))8$bI`h*2Cj
Fake flag 1 (decrypted): lactf{olhkgdfltwhgxkpddxrnxywmjvwvqzvkx}

Fake flag 2: lactf{ldkotpfuhydlqpuzhdexgahyswzzocjmh}
Fake flag 2 (encrypted): J/^L[Z[e@n1LRVuvk:2OO99&KVj2NVx]B54~@WOy

The text on the stone begins to rearrange itself into another message:
lactf{tHeY_SaiD_l!NaLg_wOuLD_bE_fUN_115}
```

### Conclusions

In both cases, we get our real flag: `lactf{tHeY_SaiD_l!NaLg_wOuLD_bE_fUN_115}`.
I thought it was interesting how this challenge could be solved multiple ways, but I guess that's just the power of linear algebra :)