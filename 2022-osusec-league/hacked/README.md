# hacked

> Jimothy came back to his computer after lunch and logged in to see some processes running he didn't open. He saw a note on the desktop saying something about him being hacked. He called IT and they were able to grab a memory dump of the device before they asked Jimothy to unplug the machine. Can you figure out what the attackers were doing on the machine?

Provided: [memory_dump.zip](https://drive.google.com/uc?id=1s-WlTc92lF0TDHzXGpf7l0DZrluf4DYT&export=download)

## Solution

The challenge author recommended [Volatility](https://www.volatilityfoundation.org/releases-vol3) to analyze the memory dump, so I started off by downloading that.
First things first, let's check which processes were running at the time of the memory dump (obviously extracting it first haha):

```shell
$ unzip memory_dump.zip
  inflating: memory_dump.raw
$ python vol.py -f memory_dump.raw windows.pslist
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output
# ...among many others...
1252	3256	firefox.exe	0xd08ae5080080	0	-	   1	False	2023-02-06 16:54:35.000000 	2023-02-06 16:54:39.000000 	Disabled
4364	7892	powershell.exe	0xd08ae5a14080	9	-	   3	False	2023-02-06 20:28:00.000000 	N/A	Disabled
1348	4196	notepad.exe	0xd08ae7bb3080	1	-	   3	False	2023-02-06 20:28:10.000000 	N/A	Disabled
```

I only kept the processes that looked interesting since there were a lot running :)
I ended up checking out notepad's memory first which turned out to be the right choice, so let's dump itto a more readable format:

```
$ python vol.py -f memory_dump.raw windows.memmap --pid 1348 --dump
# ...lots of output that I can't include...
0xfa8f4adc6000	0x966dc000	0x1000	0xfa8f4adc6000	pid.1348.dmp
0xfa8f4adc7000	0x4badb000	0x1000	0xfa8f4adc7000	pid.1348.dmp
0xfa8f4adc8000	0x5f3da000	0x1000	0xfa8f4adc8000	pid.1348.dmp
0xfa8f4adc9000	0x1295d9000	0x1000	0xfa8f4adc9000	pid.1348.dmp
0xfa8f4adca000	0x1069cf000	0x1000	0xfa8f4adca000	pid.1348.dmp
0xfa8f4a08f000	0x25144000	0x1000	0xfa8f4a08f000	pid.1
```

I spent a while trying to figure out how to parse that memory dump with volatility but then realized that I could just run `strings` on it :) Since we're looking for the flag, why not grep for the string `flag`?

```
$ strings pid.1348.dmp | grep flag
# ...lots of outputs seems to be a common theme lol...
The flag is the ntlm hash of the user wrapped.
Ex: flag{miH7CvSGyutSFtQB6w3AshXaDjbuqktXUQ}
The flag is the ntlm hash of the user wrapped.
Ex: flag{miH7CvSGyutSFtQB6w3AshXaDjbuqktXUQ}
parameters=configdir='sql:C:\\Users\\Administrator\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\08lbqkfn.default-release' certPrefix='' keyPrefix='' secmod='secmod.db' flags=optimizeSpace updatedir='' updateCertPrefix='' updateKeyPrefix='' updateid='' updateTokenDescription='' 
START: Install flag 0x%08x, flagex 0x%08x
The flag is the ntlm hash of the user wrapped.
Ex: flag{31d6cfe0d16ae931b73c59d7e0c089c0}
# hint: more output
```

Hmm...I've never heard of an NTLM hash before. [Looks like they're related to authentication on domains?](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview).
Luckily volatility has a [`hashdump`](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#hashdump) command that gives us what we need :)

```
$ python vol.py -f memory_dump.raw windows.hashdump
# ...lots of stuff about scanning...
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	296788975c1ce6fafb8221f54f5aa68c
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	67594cc62423c1d68acd9b5620eec6d0
Jimothy	1000	2d60630381393c46ac2e9b858d5427bc	80a1850fba580325595eb75c2ec50207
```

So there's an NT hash *and* an LM hash?
I also took "the user wrapped" from the `strings` output literally and was confused why there was no user named `wrapped`, but then I realized that Jimothy was the one that got hacked so it was probably his hash that we need.
I (again arbitrarily) chose to submit Jimothy's `nthash` as a flag and that ended up being correct: `osu{80a1850fba580325595eb75c2ec50207}`.
Honestly I didn't really understand most of this but now I am curious about it so I guess that's something :)
