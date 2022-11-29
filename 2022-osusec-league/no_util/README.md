# no_util

> My friend says software bloat increases attack surface area, but this is a bit crazy...

## Solution

When we ssh into the machine at the provided URL, we're provided with a nice prompt:

```text
GNU Coreutils are too bloated.
That's why minimalists use Busybox.
But the TRUE masters don't even need that.

flag.txt is around here somewhere ~_~
but I lost it in this cluttered filesystem o_o
can you help me find it? UwU

^-^
```

Trying to run some basic commands leaves us with little hope, but luckily some builtins still exist:

```shell
^-^ ls
bash: ls: command not found
^-^ echo $SHELL
/bin/ash
```

Huh, that's weird: we're running bash but the $SHELL environment variable was changed to /bin/ash for some reason.
Luckily we can ask for some help by typing `help`, which gives us a list of bash's builtins.
Unfortunately `find` isn't one of these, so we're going to have to find a way to reinvent it from what we are given.

Bash's globbing feature proved to be very useful in doing this challenge, as it allows us to bring back a surprising amount of functionality offered by something like GNU coreutils or busybox.
In case you don't know what globbing is, bash and some other shells expand something like `flag.*` into all files that start with `flag.` in the current directory. As an example:

```shell
$ ls
flag flag.bin flag.txt not_matched.txt
$ echo flag.*
flag.bin flag.txt
```

You can also prepend `flag.*` (or whatever globbing pattern) with a series of directories to expand to all matching files in a specific directory. This actually lets us reimplement the `ls` command using something like this:

```bash
function ls {
    echo $1/*;
}
```

Note: this does ignore hidden files (files whose names start with `.`, e.g. `.bashrc`), but we can ignore those since the flag file is known not to be hidden (it's called `flag.txt`).

The `$1` here represents the first argument provided to the function (e.g. "/root" if it's called as `ls /root`). Each successive number (`$2`, `$3`, etc.) represents another argument in bash.

For our find implementation we need to be able to do two things: recursively search directories and find a file (not a directory, flagtastic\_falafel made me paranoid) whose name is `flag.txt`.
We can use globbing for the former, but we also need to iterate over the results of the globbing, which is where bash's `for` builtin comes in. As an example, here's a (more verbose) implementation of `ls` using a for loop (note that it only lists files in the current directory):

```bash
for file in *; do
    echo $file;
done
```

We can't (well, shouldn't) just recursively glob every path we encounter, though, since files can't contain anything, for example. This is where bash's `test` builtin comes in (or its counterparts `[`/`]`). Using a variety of flags, you can test for a bunch of different conditions, but here are the ones that are useful for this challenge:

- `-d` checks if a file is a directory
- `-f` checks if a file is a regular file (whatever that is :))
- `-L` checks if a file is a symbolic link
- `-a` is essentially the logical and operator: it checks of both of two conditions are true
- `!` is the logical not operator: it negates whatever condition follows it

The symlink one is to avoid infinite recursion, since I think I encountered a directory that contained a symlink to itself or something without it.

Obviously we need to be able to different things based on whether our `test`s evaluate to true or false, which bash has the `if` builtin for.

The last thing we need is to actually check if we've found the flag. I decided to use regular expressions to check if each file was named `flag.txt`, but you could also use something like `test`'s `-e` flag to check if `flag.txt` existed in the current directory, for example. I think you need to use `[[`/`]]` for regular expression matching, since their help page was the only one that mentioned the match operator, `=~`.

Combining all of those, we can finally reimplement find! (or at least its basic functionality haha)

```bash
function find_flag {
    # Iterate over all files in the provided directory via globbing
    for file in $1/*; do
        # Check if $file is a directory and not a symlink to avoid infinite recursion
        if test -d $file -a ! -L $file; then
            # Search $file (which we know is a directory) for flag.txt
            find_flag $file;
        # Check if $file is a regular file & is named (i.e. the full path ends with) flag.txt
        elif test -f $file && [[ $file =~ flag.txt$ ]]; then
            # Echo the flag filename if we found it
            echo $file;
        fi;
    done;
}
```

Now for the moment of truth:

```shell
^-^ find_flag
bash: test: too many arguments
bash: test: too many arguments
bash: test: too many arguments
bash: test: /sys/bus/mdio_bus/drivers/Generic: binary operator expected
bash: test: too many arguments
bash: test: too many arguments
bash: test: too many arguments
bash: test: /sys/bus/pnp/drivers/i8042: binary operator expected
bash: test: too many arguments
bash: test: /sys/bus/pnp/drivers/i8042: binary operator expected
bash: test: too many arguments
bash: test: too many arguments
/usr/lib/share/misc/flag.txt
```

And now we have our flag path! Who cares about those errors anyways :) Now to get its contents:

```shell
^-^ cat /usr/lib/share/misc/flag.txt
bash: cat: command not found
```

...oh, right.

There aren't any builtins per se that can help us here, but luckily we do have one more trick up our sleeves: input redirection and command substitution (ok maybe two tricks).
Input redirection is accomplished via the `<` operator, which essentially provides the contents of a file to a program's standard input.
For example, the following would normally be equivalent if we had the `cat` command handy (I think):

```shell
$ cat file | wc -l
$ wc -l < file
```

Technically `wc -l file` would also work but it might not with other programs :)
`echo` is unfortunately one of those programs:

```shell
^-^ echo < /usr/lib/share/misc/flag.txt

^-^
```

With command subsitution, though, we can actually get the contents of the file and supply them to `echo`, since it just prints whatever it receives.
[This StackOverflow answer](https://stackoverflow.com/a/9387914) as well as the [GNU bash manual](https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html) both let us know how to do this: `$(< file)`. Apparently it's more efficient than `$(cat file)` I guess?

Now that we can get the contents of the flag file, let's print them out :)
```shell
^-^ echo $(< /usr/lib/share/misc/flag.txt)
osu{b4$h_i5_p1en7y}
```

And there's our flag! This challenge was probably one of the less practical ones but it was still lots of fun to learn more about how bash's builtins can be assembled in different ways :)
