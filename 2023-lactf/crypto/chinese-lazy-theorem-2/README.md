# crypto/chinese-lazy-theorem-2 (165 solves/391 points)

> Ok I'm a little less lazy now but you're still not getting much from me.

Provided: [`chinese-lazy-theorem-2.py`](chinese-lazy-theorem-2.py)

## Solution

This challenge is similar to [its prequel](../chinese-lazy-theorem-1/README.md), but obviously not exactly the same.
We're now given 2 oracle queries, and n is defined slightly differently:

```python
p = getPrime(512)
q = getPrime(512)
n = p*q*2*3*5
```

The author also properly bounded the modulus we send in this time, so we can no longer cheese that way:

```python
            # snip
            elif modulus > max(p, q):
                print("something smaller pls")
                print()
```

We can still send in p and q as moduli, though, which almost gives us enough information to recover target because of the [Chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) mentioned in the last challenge, which basically allows you to solve a set of modular equations of a specific form.
The additional `2*3*5` factor of n does complicate things slightly, but as it turns out we can still guess the proper value for target because we're given exactly enough guesses (2\*3\*5 = 30).
We just have to do 30 runs of the Chinese remainder theorem with the remainders we get relative to p and q, as well as every possible remainder resulting from division by 30 (i.e. 0 to 29).

I ended up using sage for my solve script since it provides the `crt` function for doing the Chinese remainder theorem, but you could just as easily use something like sympy.
You can view my [solve script](bit_less_lazy.sage) which does basically everything I've said up to this point.
Running it does indeed get us the flag:

```shell
$ sage bit_less_lazy.sage
modp = 7423040931335409627109420880969457244761851983489581858873556183951314926428988065765073366832607764950945672919228865218390650451571198834090324726129461
modq = 3675708324672545519560861780609911952577644806309192449514748070430154814937782838966975203482948855854446712846882272578338383493808629738646827766991067
guessing 30 remainder...
lactf{n0t_$o_l@a@AzY_aNYm0Re}
```

Neat! I would argue that the Chinese remainder theorem isn't the lazy one here, but rather the challenge author (with all due respect) :)
