# HashGuard — Sentinel

A lightweight, signature-based antivirus prototype written in C. It walks
directory trees, fingerprints files with SHA-256, matches them against a
threat-intelligence signature database, quarantines confirmed hits, and uses a
small heuristic AI layer to flag anything the signatures miss.

[![Language](https://img.shields.io/badge/language-C11-blue)](#)
[![Build](https://img.shields.io/badge/build-CMake%20%7C%20MSVC%20%7C%20GCC-green)](#)
[![CI](https://github.com/cyberx801/antivirus/actions/workflows/build.yml/badge.svg)](https://github.com/cyberx801/antivirus/actions)
[![Deps](https://img.shields.io/badge/deps-OpenSSL%2C%20libcurl-orange)](#)
[![Status](https://img.shields.io/badge/status-prototype-yellow)](#)

```
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ███████║███████║███████╗███████║██║   ██║██║   ██║███████║██████╔╝██║  ██║
  ██╔══██║██╔══██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║  ██║██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

## Features

- **Recursive directory scanning** with a configurable worker-thread pool
  (`--threads N`); cross-platform (Win32 API on Windows, `nftw` on POSIX).
- **SHA-256 / SHA-1 / MD5 fingerprinting** via OpenSSL, computed in a single
  pass over each file.
- **Bloom filter + UTHash** signature store: fast rejection of clean hashes,
  exact verification of candidate hits (per-algorithm keys).
- **Heuristic AI engine**: Shannon-entropy scoring of the file head plus a
  risky-extension profile; optional LLM confirmation via any
  OpenAI-compatible chat API.
- **Quarantine and restore**: infected files are moved out of the way
  (`--quarantine`) and can be brought back with `restore`.
- **Whitelist**: `data/whitelist.txt` skips matching paths during scans.
- **Real-time watcher** (`watch`): monitors a directory and checks new or
  modified files on the fly (ReadDirectoryChangesW / inotify).
- **YARA engine** (`yara`): optional libyara integration for rule-based
  detection (built when libyara is available).
- **JSON report** (`data/report.json`): per-file status, hash, AI score and
  entropy, always emitted as valid, escaped JSON.
- **Self-updating signatures**: downloads threat-intel feeds with a 7-day
  on-disk cache and de-duplication; persistent binary signature cache for
  fast startup.
- **Config file** (`data/config.txt`): default thread count, whitelist path and
  feed URLs.
- **Unit tests** via CTest.
- **CI**: GitHub Actions builds the project on Windows (MSVC) and Linux (GCC)
  on every push.

## How it works

```
 file ── SHA-256 ── Bloom filter ── not present ── CLEAN
                        |
                      maybe
                        |
                 UTHash exact lookup
                   |               |
                present        not present
                   |               |
               INFECTED        AI heuristic
             (quarantined)     (entropy + ext)
                                   |
                         suspicious / benign
```

1. Each file is hashed with MD5, SHA-1 and SHA-256.
2. The hash is probed against a **Bloom filter** — a negative answer is instant
   and exact.
3. Positive probes are confirmed with an **exact UTHash lookup**, so the
   signature layer has no false positives.
4. Files without a signature match go through the **AI module**: Shannon
   entropy of the first 64 KiB plus extension risk. Optionally, a configured
   LLM returns a one-word verdict for files already flagged suspicious.
5. Everything lands in a JSON report; infected files may be quarantined
   automatically.

Classification is three-tier: `INFECTED` (signature match, quarantined),
`SUSPICIOUS` (heuristic/AI flag, not quarantined), `CLEAN`.

## Architecture

| Module | File | Responsibility |
|---|---|---|
| CLI and banner | `src/main.c` | Commands, flags, summary output |
| Logger | `src/logger.c` | Timestamped log lines |
| Hashing | `src/hash.c` | MD5/SHA-1/SHA-256 of a file (OpenSSL EVP) |
| Signature DB | `src/sigdb.c` | Bloom filter + UTHash load/lookup + binary cache |
| Scanner | `src/scanner.c` | Threaded directory walk, verdict pipeline, whitelist |
| Report | `src/report.c` | Thread-safe JSON report writer |
| Quarantine | `src/quarantine.c` | Move, log and restore files |
| Updater | `src/update.c` | Feed download, 7-day cache, de-duplication |
| Watcher | `src/watcher.c` | Real-time directory monitoring |
| YARA engine | `src/yrscan.c` | Optional libyara rule scanning |
| AI engine | `src/ai.c` | Entropy heuristics + optional LLM hook |
| Config | `src/config.c` | key=value configuration loader |
| Thread utils | `src/threadutil.c` | Win32/pthreads mutex, condvar, threads |

## Building

### Windows (MSVC + vcpkg)

Prerequisites: Visual Studio Build Tools, CMake >= 4.0, vcpkg.

```powershell
vcpkg install openssl curl --triplet x64-windows

cmake -S . -B build -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

The project also configures directly from CLion.

### Linux (GCC)

```bash
sudo apt install libssl-dev libcurl4-openssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage

```bash
# Scan a directory with 8 worker threads; print a summary and quarantine hits
./antivirus scan ./downloads --summary --quarantine --threads 8

# Check a single file against the signature database
./antivirus check ./suspicious.exe

# Update signatures from threat-intel feeds (7-day cache)
./antivirus update

# Bring a quarantined file back into the current directory
./antivirus restore file.exe

# Watch a directory in real time and check new/modified files
./antivirus watch ./downloads

# Scan a file with a YARA ruleset (requires libyara)
./antivirus yara ./rules.yar ./target.bin

# Show info / help
./antivirus info
./antivirus --help
```

### Configuration

`data/config.txt` holds simple `key = value` settings:

```
threads = 4                     # default scan thread count
whitelist = data/whitelist.txt  # path to the whitelist file
feed = https://example.com/hashes.txt   # extra update feed (repeatable)
```

If no `feed` entries are present, the built-in keyless feed is used.

### Whitelist

Create `data/whitelist.txt` with one path substring per line. Any scanned file
whose path contains a listed substring is skipped and logged as `[SKIPPED]`.

```
# data/whitelist.txt
node_modules/
C:\Windows\
```

## AI engine

The AI layer has two parts and no Python dependency:

1. **Offline heuristics (always on)** — Shannon entropy of the first 64 KiB
   (packed or encrypted binaries are high-entropy) combined with a
   risky-extension profile (`.exe`, `.dll`, `.scr`, `.pif`, `.com`, `.vbs`,
   `.js`, `.ps1`, `.bat`, `.cmd`, `.jar`, `.msi`, `.hta`, `.wsf`).
2. **Optional LLM triage (opt-in)** — when a file is already flagged
   suspicious by the heuristic and the following environment variables are
   set, HashGuard asks an OpenAI-compatible chat API for a one-word verdict:

```bash
export HASHGUARD_AI_URL="https://api.openai.com/v1/chat/completions"
export HASHGUARD_AI_KEY="sk-..."
export HASHGUARD_AI_MODEL="gpt-4o-mini"   # optional, defaults to gpt-4o-mini
```

If the API is unreachable or unconfigured, the scan silently falls back to the
local heuristic. To keep API costs bounded, the LLM is only consulted for
files the heuristic already flagged.

## Signature feeds

The updater downloads plain-text hash feeds and extracts valid 32/40/64
character hashes (MD5/SHA-1/SHA-256). The default feed is keyless:

- [ThreatCluster](https://threatcluster.io) — high-confidence file hashes
  (last 30 days)

abuse.ch retired its unauthenticated export endpoints (HTTP 410), so the feed
table in `src/update.c` is designed to be easy to extend or replace.

## Project structure

```
.
├── CMakeLists.txt
├── README.md
├── .github/workflows/build.yml   # CI (Windows + Linux)
├── include/                      # headers, incl. vendored uthash.h
├── src/                          # C sources
├── tests/                        # unit tests (CTest)
└── data/
    ├── signatures.txt            # one hash per line (MD5/SHA-1/SHA-256, generated by update)
    ├── signatures.txt.cache      # persistent binary signature cache (generated)
    ├── config.txt                # configuration (threads, whitelist, feeds)
    ├── whitelist.txt             # skip-list for scans
    ├── cache/                    # feed cache (7 days, generated)
    └── report.json               # last scan report (generated)
```

## Roadmap

- [x] MD5 and SHA-1 signature support
- [x] Real-time directory watcher
- [x] YARA rule engine
- [x] Persistent Bloom filter cache
- [x] Config file (feeds, scan defaults)
- [x] Unit tests

## Disclaimer

This is an educational prototype, not a substitute for a real endpoint
security product. Signature feeds are community-provided, and the heuristic
AI layer is best-effort. Use at your own risk.

## License

MIT — fork it, break it, improve it.

---

*HashGuard v1.3 "Sentinel" — Fatih Özdil*
