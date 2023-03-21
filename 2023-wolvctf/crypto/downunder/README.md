# crypto/downunder (497 points/12 solves*)

(*solved after CTF ended)

> I sure hope nobody goes down on me...
>
> Make sure to gobble down our cookies though.
> https://down-under-tlejfksioa-ul.a.run.app/

Provided: [`source.zip`](source.zip)

Summary: Small subgroup confinement attack on Diffie Hellman with some HMAC brute forcing and Chinese Remainder Theorem for good measure :)

## Solution

The most interesting file from the extracted source is `key_exchange.py`, which appears to do a [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) of sorts:

```python
# lines 40-46 of key_exchange.py
def diffie_hellman(A, g, b, p):
    B = pow(g,b,p)
    s = pow(A,b,p)
    message = b'My totally secure message to Alice'
    password = long_to_bytes(s)
    my_hmac = new(key=password, msg = message, digestmod=sha256)
    return str(bytes_to_long(my_hmac.digest())), B
```

The goal of this challenge is to find the value of `b`, which is an integer representation of the flag:

```python
f = open("flag.txt", "r")
flag = f.read().strip()
b = bytes_to_long_flag(flag.encode('utf-8'))
```

We're able to provide a value for `A` as a query parameter to the provided URL, which then gives us a JSON response that looks something like this:

```json
{
  "B": 2.3814282832066086e+273,
  "g": 2.1925400413388894e+273,
  "hmac": "91368064761969554193146310664428696779669778217293388427175887610826255556020",
  "p": 2.944391651859508e+273,
  "q": 8.613760276862309e+40
}
```

We are given the full numbers (i.e. not just the scientific notation), but that's what the JSON looks like when pretty printed so :)

My first idea was to send 1 and -1 as `A` values to determine if the flag exponent was even or odd, since -1 to any even power is just 1, so the HMAC values generated as shown above would be the same in that case.
As it turns out, the flag exponent is in fact even, which makes sense based on how the flag is converted to a number, assuming it ends in a `}` character.

At this point I was a bit stumped, but when randomly lookup up stuff to find any leads I found a [writeup by Project Sekai](https://sekai.team/blog/wolvsec-ctf/cpa/) from last year's WolvSec CTF that seemed to be really similar.
I'd highly recommend giving it a read if you have a chance (thanks again to @sahuang for explaining the challenge so well :D).

It essentially boils down to a consequence of [Cauchy's Theorem](https://en.wikipedia.org/wiki/Cauchy%27s_theorem_(group_theory)), which implies that any group of composite order has subgroups with their orders being the prime factors of the order of the entire group (if that makes sense).
If you're not familiar with group theory (if not I don't blame you haha), the order of a group is the number of elements it has, which for the multiplicative group of integers mod a prime $p$ is $p-1$ as a consequence of [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem) (at least I think lol).
The order of a specific element of a group is how many times the group operation (in this case multiplication) can be applied to it before arriving at the group identity (1 for multiplication).

Because $p$ is prime in that case, though, $p-1$ has to be composite since it at the very least has to be even.
In the context of this challenge, $p-1$ consistently appears to have 7 small(ish) prime factors:

```python
>>> from sympy import primefactors
>>> p = 2944391651859508220032914208161471056786614311862501680986963364297699599329788924893003846095489297754340082139509854389526154622496939661259152806710216023823737242149467908480946748733106681479664581152675420961752622839506627347334048941289384274114219119358191643637203
>>> primefactors(p-1, limit=100000)
[2, 38971, 41077, 42853, 48751, 62497, 62687]
```

Note that those aren't all of the prime factors of $p-1$; in this case, $p$ also has another composite factor on the order of $10^{246}$, but sympy wasn't having a fun time factoring it so we can ignore it for now :)

As I mentioned above, Cauchy's Theorem guarantees subgroups of $\mathbb{Z}_p^\times$ (the multiplicative group of integers mod $p$) with orders equal to each of those factors.
Now, how is that useful?
Well, if you have an element $a$ of one of those subgroups with order $w$, raising it to the power of $b$ (the flag exponent) is the same as raising it to the power of $kw + r$, which simplifies like so:

```math
\begin{align}
a^b \mod p &= a^{kw+r} \
           &= a^{kw}a^r \
           &= (a^w)^ka^r \
           &= 1^ka^r \
           &= a^r \mod p
\end{align}
```

Notice that $r \equiv b \mod w$, so if we have enough of those residuals we can use the Chinese Remainder Theorem to recover the flag completely!
We can find the specific residuals by brute forcing the resulting HMAC of that exponentiation, which is doable because the factors of $p-1$ (the group order) are relatively small, especially when compared to $p-1$ :)

That still leaves the problem of finding elements of those subgroups, but luckily some more research yielded [this Cryptography Stack Exchange post](https://crypto.stackexchange.com/q/27584), which says that for a given generator of $\mathbb{Z}_p^\times$ and factor $w$ of its order, $g^{\frac{p-1}{w}}$ will lie in the subgroup of order $w$.

With all of that knowledge in hand, we can then recover the flag exponent and therefore the flag!
You can check out my entire solve script [here](confine.py).
Running it does indeed give us the flag :)

```shell
$ python confine.py
Current iteration factors: [38371, 40847, 47017, 52051, 54293, 62273]
Testing factor: 38371
Found remainder! 33866
Testing factor: 40847
Found remainder! 25035
Testing factor: 47017
Found remainder! 39343
Testing factor: 52051
Found remainder! 22926
Testing factor: 54293
Found remainder! 8832
Testing factor: 62273
Found remainder! 9240
Current iteration factors: [37159, 38281, 41047, 57173, 57241, 61717]
Testing factor: 37159
Found remainder! 28255
Testing factor: 38281
Found remainder! 32053
Testing factor: 41047
Found remainder! 20995
Testing factor: 57173
Found remainder! 50836
Testing factor: 57241
Found remainder! 55644
Testing factor: 61717
Found remainder! 53992

Flag found! wctf{m4x1mum_l3ngth5!}
```

And there's our flag!
This was honestly a super interesting challenge and I definitely learned a lot from it :)