---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
ctf: ""           # nome del CTF, es. "picoCTF 2024"
category: "pwn"   # pwn | rev | crypto | forensics | misc | web
difficulty: ""    # easy | medium | hard
points: 0
tags: []
description: ""
---

## Overview

Breve descrizione della challenge.

## Recon

```bash
$ file challenge
$ checksec challenge
```

## Analysis

...

## Exploit

```python
from pwn import *

elf = ELF('./challenge')
p   = process('./challenge')

# ...

p.interactive()
```

## Result

<div class="flag-box">CTF{flag_here}</div>

## Takeaways

- Cosa hai imparato
