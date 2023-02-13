# crypto/hill-hard (31 solves/485 points)

> I found another rock. I tried smashing it with a hammer, but it's really hard this time.

Provided: [chall.py](chall.py)

Solve script: [hard_rock.sage](hard_rock.sage)

## Solution

This challenge is relatively similar to its easier counterpart, but there are a couple key differences:

- We only get 14 encryption oracle queries, not 20 (well, 10 with two encryptions each)
- The fake flags (and our queries) are now 20 characters instead of 40
- Spaces are banned so no more cheese :(
- The queries we send in are xored componentwise with the first fake flag

I got caught on the xoring for a while, but figured out pretty quickly that if you send a vector wrapped in `lactf{...}` then you essentially cancel it during when xoring, allowing you to focus on the "inside" of the flag so to speak.
The problem with xoring, though, is that its effect depends on the random letters in the first fake flag which we don't know.
We do know that all of those letters are lowercase, though, and based on [this ASCII table](https://www.binaryhexconverter.com/binary-ascii-characters-table) all lowercase letters have the 32 bit as a 1 in their binary representation.
This means that subtracting 32 as is done in `stov` will effectively just set that bit to zero.
If we can find a character that gets converted to 32 in `stov`, it will then allow us to affect all of the letters inside the `lactf{...}` wrapper in the same way, allowing us to glean information about the $\mathbf{A}$ matrix.
Such a character would need an ASCII codepoint of 64, which as it turns out is the `@` symbol.
All lowercase letters also have the 64 bit as a 1 in their ASCII codepoints, meaning that the character with codepoint 64 + 32 = 96 (`` ` ``) will similarly affect all of the flag letters in the same way.

Out of curiosity, I checked how this xoring would affect the resulting vector components:

```python
>>> ((ord("c") - 32) ^ 32) % 95 # corresponds to @
4
>>> ((ord("c") - 32) ^ 64) % 95 # corresponds to `
3
```

This difference of 1 is actually really convenient, since can then recover the relevant columns of $\mathbf{A}$ by taking differences between encrypted vectors.

In the end, my oracle queries ended up looking like this:

- `lactf{@@@...@@@}`
- ``lactf{`@@...@@@}``
- ``lactf{@`@...@@@}``
- ...
- ``lactf{@@@...@`@}``
- ``lactf{@@@...@@`}``

As I mentioned previously, the `lactf{...}` wrapper gets canceled during the xoring process.
The first query acts as a baseline to subtract the other ones from.
Because only one character differs between this baseline and every other query, simple subtraction can be used to recover each of the corresponding columns of $\mathbf{A}$ like I mentioned earlier.

Even with those columns, though, we still need to figure out how to account for the `lactf{...}` wrapper that I've been sweeping under the rug.
First, we can observe a property of the encryption process, since it is just matrix multiplication (neglecting the xoring that takes place for our oracle queries).
Let $\mathbf{v}$ be the vector being encrypted, $c_i$ be the `i`th character of that vector, and $|c|$ represent the ASCII codepoint of the character $c$:

```math
\text{Enc}(\mathbf{v}) =
\mathbf{A}\mathbf{v} = \mathbf{A}
\begin{pmatrix}
|\text{l}| - 32 \\
|\text{a}| - 32 \\
|\text{c}| - 32 \\
... \\
|c_{19}| - 32 \\
|\text{\}}| - 32
\end{pmatrix} =

\mathbf{A}
\begin{pmatrix}
|\text{l}| \\
|\text{a}| \\
|\text{c}| \\
... \\
|c_{19}| \\
|\text{\}}|
\end{pmatrix} -

\mathbf{A}
\begin{pmatrix}
32 \\
32 \\
32 \\
... \\
32 \\
32
\end{pmatrix}
```

If we could somehow recover vectors similar to those on the right except just for the inner random letters of the first fake flag, we could then determine the vector contribution of the `lactf{...}` wrapper to the result of this matrix multiplication.
Well, the second vector is relatively trivial to compute: we just need to multiply our recovered matrix (let's call it $\mathbf{A}'$) by a vector whose components are all 32.
The first vector is actually exactly the result we got from encrypting `lactf{@@@...@@@}` with the oracle, since as mentioned previously xoring lowercase letters (after subtraction of 32) with 32 is basically equivalent to adding 32 to the character's codepoint.

With that in mind, recovering the outer contribution vector $\mathbf{o}$ is relatively trivial:

```math
\mathbf{o} = \mathbf{f}_1 - \mathbf{b} + \mathbf{A}'\mathbf{v}_{32}
```

Where $\mathbf{f_1}$ is the fake first flag encrypted, $\mathbf{b}$ is our baseline vector (i.e. result from querying the oracle with `lactf{@@@...@@@}`), and $\mathbf{v}_{32}$ is a vector with 13 elements that are all 32.

We can then encrypt an arbitrary 20-character flag (like the second fake flag we're sent) like so:

```math
\text{Enc}'(\mathbf{v}) = \mathbf{o} + \mathbf{A}'
\begin{pmatrix}
|v_7| - 32 \\
|v_8| - 32 \\
|v_9| - 32 \\
... \\
|v_{19}| - 32
\end{pmatrix}
```

Where $v_7...v_{19}$ are the lowercase letters inside the `lactf{...}` wrapper, and again $|v_i|$ is the ASCII codepoint of the ith character of $\mathbf{v}$.

With that knowledge in hand, we can finally get the real flag!

```shell
$ sage hard_rock.sage
fake flag 1 (encrypted): jGk3@Rl WvxYIkwK'@L[
fake flag 1 (decrypted): lactf{ixrbwrzwjowlv}

fake flag 2: lactf{lbnwvikrlowfn}
fake flag 2 (encrypted): r%v]:TEkEKW+,'LfTYES

Your vision fades to black, and arcane symbols begin to swarm your mind. To others, it might seem like magic, but you can see what others cannot.
lactf{putting_the_linear_in_linear_algebra}
```

I'm kinda surprised that I was able to do this despite never taking a linear algebra course but it was a lot of fun to finally solve, even if I might have gone a bit insane along the way :)