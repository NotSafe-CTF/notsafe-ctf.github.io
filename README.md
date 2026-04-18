# l30 — CTF Blog

Dark minimal security research blog built with **Hugo** + **GitHub Pages**.

## Quick start

### 1. Install Hugo

```bash
# Arch Linux
sudo pacman -S hugo

# macOS
brew install hugo

# oppure scarica il binario da https://github.com/gohugoio/hugo/releases
```

### 2. Clona e avvia in locale

```bash
git clone https://github.com/yourusername/yourusername.github.io
cd yourusername.github.io
hugo server -D
# → http://localhost:1313
```

---

## Aggiungere un write-up

### Metodo 1 — archetype (raccomandato)

```bash
hugo new writeups/nome-challenge.md
```

Apri `content/writeups/nome-challenge.md` e compila i campi frontmatter:

```yaml
---
title: "ROP Emporium — split"
date: 2024-11-15
ctf: "ROP Emporium"
category: "pwn"       # pwn | rev | crypto | forensics | misc | web
difficulty: "easy"
points: 0
tags: ["rop", "pwn", "x86-64"]
description: "Breve descrizione per l'anteprima."
---
```

### Metodo 2 — file diretto

Crea qualsiasi file `.md` in `content/writeups/` con il frontmatter sopra.
Hugo lo rileva automaticamente, lo ordina per data e lo linka in home page.

---

## Deploy su GitHub Pages

### Prima volta

1. Crea repo `yourusername.github.io` su GitHub
2. Vai su **Settings → Pages → Source** → seleziona **GitHub Actions**
3. Push:

```bash
git init
git remote add origin https://github.com/yourusername/yourusername.github.io.git
git add .
git commit -m "init blog"
git push -u origin main
```

GitHub Actions builderà e deployerà automaticamente.

### Ogni write-up successivo

```bash
# scrivi il write-up in content/writeups/challenge.md
git add .
git commit -m "writeup: nome challenge"
git push
# → sito aggiornato in ~30 secondi
```

---

## Struttura

```
.
├── archetypes/
│   └── writeups.md          ← template per nuovi write-up
├── content/
│   ├── whoami.md            ← pagina "Who I am"
│   └── writeups/
│       ├── _index.md
│       ├── challenge1.md    ← i tuoi write-up qui
│       └── challenge2.md
├── layouts/
│   ├── _default/
│   │   ├── baseof.html      ← base HTML (navbar, footer)
│   │   └── single.html      ← layout pagine generiche
│   ├── partials/
│   │   ├── nav.html
│   │   └── footer.html
│   ├── writeups/
│   │   ├── list.html        ← pagina /writeups/
│   │   └── single.html      ← singolo write-up
│   └── index.html           ← home page
├── static/
│   ├── css/main.css
│   └── js/main.js
├── .github/
│   └── workflows/hugo.yml   ← GitHub Actions auto-deploy
└── hugo.toml                ← config (cambia baseURL e author)
```

---

## Personalizzazione

### Cambia nome/username

In `hugo.toml`:

```toml
baseURL = "https://yourusername.github.io/"
title   = "yourname | Security Research"

[params]
  author = "yourname"
  github = "https://github.com/yourusername"
```

### Cambia la bio

Modifica `content/whoami.md` — HTML + Markdown funzionano entrambi.

### Highlight syntax

Il tema Monokai è già configurato. Usa triple backtick con il linguaggio:

````markdown
```python
from pwn import *
```
````

### Flag box

Usa questo HTML inline nel Markdown:

```html
<div class="flag-box">CTF{la_tua_flag}</div>
```

---

## Colori del tema

| Variabile      | Hex       | Uso                  |
|----------------|-----------|----------------------|
| `--accent`     | `#7fff7f` | verde principale     |
| `--red`        | `#ff5555` | categoria rev/danger |
| `--cyan`       | `#8be9fd` | CTF name, codice     |
| `--purple`     | `#bd93f9` | tag secondari        |
| `--yellow`     | `#f1fa8c` | highlight            |

Palette ispirata a Dracula — funziona bene con terminali.
