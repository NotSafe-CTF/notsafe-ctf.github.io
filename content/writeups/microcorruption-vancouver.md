---
title: "Microcorruption — Vancouver"
date: 2024-10-22
ctf: "Microcorruption"
category: "rev"
difficulty: "easy"
tags: ["msp430", "rev", "embedded", "microcorruption"]
description: "First Microcorruption level — understanding the MSP430 lock routine."
---

## Overview

Vancouver is the introductory Microcorruption level. It introduces the MSP430
architecture and the debugger interface. The goal is to unlock the door by finding
the correct password.

## Analysis

The `check_password` function compares user input against a hardcoded string:

```asm
4484 <check_password>
4484:  bf90 7465 0000   cmp	#0x6574, 0x0(r15)   ; "te"
448a:  0d20             jnz	$+0x1c
448c:  bf90 7374 0200   cmp	#0x7473, 0x2(r15)   ; "st"
4492:  0920             jnz	$+0x14
```

MSP430 is **little-endian** — `0x6574` in memory is the bytes `74 65` = `"te"`.
Reading the pairs in order gives us the password.

## Solving

Password: `test` (trivially visible in the comparison immediates).

## Takeaways

- MSP430 is little-endian — byte order matters when reading `cmp` immediates
- Microcorruption's debugger makes it trivial to step through and spot hardcoded values
- This is the "hello world" of embedded RE
