# 🛡 HashGuard — Sentinel

> **A lightweight, signature-based antivirus prototype in C.**
> Scan files, hash them with SHA-256, match them against a threat-intel signature database, quarantine the bad guys — and let a tiny AI heuristic sniff out anything the signatures miss.

![Language](https://img.shields.io/badge/language-C11-blue)
![Build](https://img.shields.io/badge/build-CMake%20%2B%20MSVC%20%7C%20GCC-green)
![Deps](https://img.shields.io/badge/deps-OpenSSL%2C%20libcurl-orange)
![Status](https://img.shields.io/badge/status-prototype-yellow)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

```
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ███████║███████║███████╗███████║██║   ██║██║   ██║███████║██████╔╝██║  ██║
  ██╔══██║██╔══██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║  ██║██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

## ✨ Features

- 🔍 **Recursive directory scanning** — cross-platform (Win32 API / POSIX `nftw`)
- 🔐 **SHA-256 fingerprinting** via OpenSSL
- ⚡ **Bloom filter + UTHash** — O(1)-style signature lookup over huge databases
- 🧠 **AI heuristics** — Shannon-entropy scoring + extension risk profile, with an optional LLM (OpenAI-compatible) triage hook
- 🚨 **Quarantine** — infected files are moved away and logged (`--quarantine`)
- 📊 **JSON report** — per-file status, hash, AI score and entropy (`data/report.json`)
- 🔄 **Self-updating signatures** — pulls threat-intel feeds with a 7-day cache
- 🎨 Fancy ANSI banner (because why not)

## 🧱 How it works

```
 file ──► SHA-256 ──► Bloom filter? ──no──► CLEAN
                        │yes (maybe)
                        ▼
                 UTHash exact match?
                   │ yes            │ no
                   ▼                ▼
                INFECTED      AI heuristic (entropy + ext)
                (quarantine)        │
                                    ▼
                             SUSPICIOUS / CLEAN
```

1. Every file is hashed (SHA-256, 1 KB streaming chunks).
2. The hash is probed against a **Bloom filter** (fast negative answer).
3. Possible hits are verified with an **exact UTHash lookup** — no false positives.
4. Signature misses are passed to the **AI module**: Shannon entropy of the file head + risky-extension score. Optionally, a configured LLM confirms the verdict.
5. Results land in a valid, escaped **JSON report**; infected files can be quarantined automatically.

## 🏗 Architecture

| Module | File | Responsibility |
|---|---|---|
| CLI & banner | `src/main.c` | Argument parsing, commands, summary |
| Logger | `src/logger.c` | Timestamped log lines |
| Hashing | `src/hash.c` | SHA-256 of a file (OpenSSL) |
| Signature DB | `src/sigdb.c` | Bloom filter + UTHash, load/lookup/free |
| Scanner | `src/scanner.c` | Recursive directory walk + verdict pipeline |
| Report | `src/report.c` | JSON report generation |
| Quarantine | `src/quarantine.c` | Move + log malicious files |
| Updater | `src/update.c` | Feed download, 7-day cache, dedup, metadata |
| AI engine | `src/ai.c` | Entropy heuristics + optional LLM hook |

## 🔧 Build

### Windows (MSVC + vcpkg)

```powershell
# prerequisites: Visual Studio Build Tools, CMake >= 4.0, vcpkg with openssl + curl
vcpkg install openssl curl:x64-windows

cmake -S . -B build -G Ninja ^
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

> The project also configures cleanly from **CLion** (CMake 4.0 bundle).

### Linux (GCC)

```bash
sudo apt install libssl-dev libcurl4-openssl-dev
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

## 🚀 Usage

```bash
# Scan a directory, print a summary and quarantine threats
./antivirus scan ./downloads --summary --quarantine

# Check a single file
./antivirus check ./suspicious.exe

# Update signatures from threat-intel feeds (7-day cache)
./antivirus update

# Show info / help
./antivirus info
./antivirus --help
```

## 🤖 AI engine

Two layers, no Python required:

1. **Offline heuristics (always on)** — Shannon entropy of the first 64 KiB
   (packed/encrypted binaries are high-entropy) combined with a risky-extension
   profile (`.exe`, `.dll`, `.scr`, `.vbs`, `.ps1`, `.js`, …).
2. **Optional LLM triage (opt-in)** — when a file is already flagged suspicious
   and these environment variables are set, HashGuard asks an
   OpenAI-compatible chat API for a one-word verdict:

```bash
export HASHGUARD_AI_URL="https://api.openai.com/v1/chat/completions"
export HASHGUARD_AI_KEY="sk-..."
export HASHGUARD_AI_MODEL="gpt-4o-mini"   # optional, defaults to gpt-4o-mini
```

If the API is unreachable or unconfigured, the tool silently falls back to the
local heuristic — it never breaks the scan.

## 📦 Signature feeds

The updater downloads plain-text hash feeds and extracts valid 64-char SHA-256
entries. Currently configured with a **keyless** public feed:

- [ThreatCluster](https://threatcluster.io) — high-confidence file hashes (last 30 days)

> Note: abuse.ch retired its unauthenticated export endpoints (HTTP 410), so
> feeds are easy to swap — just edit the `FeedSource` table in `src/update.c`.

## 📁 Project structure

```
.
├── CMakeLists.txt
├── README.md
├── include/          # headers (incl. vendored uthash.h)
├── src/              # C sources
└── data/
    ├── signatures.txt        # one SHA-256 per line (generated by `update`)
    ├── cache/                # downloaded feed cache (7 days)
    └── report.json           # last scan report (generated)
```

## 🗺 Roadmap

- [ ] Parallel scanning (thread pool)
- [ ] MD5/SHA-1 signature support
- [ ] Restore-from-quarantine command
- [ ] YARA rule engine
- [ ] Real-time directory watcher
- [ ] Config file & whitelist
- [ ] CI pipeline (Windows + Linux)

## ⚠️ Disclaimer

This is an **educational prototype**, not a substitute for a real endpoint
security product. Signature feeds are community-provided; the AI heuristic is
best-effort. Use at your own risk.

## 📄 License

MIT — feel free to fork, break, and improve.

---

*Crafted by **Fatih Özdil** — HashGuard v1.1 "Sentinel"*
