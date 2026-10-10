# Necropsy

![Python](https://img.shields.io/badge/python-3.10+-blue)
![C++](https://img.shields.io/badge/C%2B%2B-17-blue)
![C%23](https://img.shields.io/badge/C%23-.NET%208-purple)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

Crash dump triage pipeline. Parses Windows minidumps, classifies each crash by exploitability, and generates ranked reports. Three layers:

- **C++ engine** — fast minidump parser + triage rules, emits JSON
- **C# GUI** — WinForms front-end for single or batch analysis
- **Python orchestrator** — batch mode, report generation (JSON/CSV/MD/HTML)

## What it does

- Parses `.dmp` files (x64 user-mode minidumps) natively
- Extracts exception record, faulting thread's x64 registers, loaded modules, OS info
- Classifies each crash: `EXPLOITABLE` / `PROBABLY_EXPLOITABLE` / `UNKNOWN` / `NOT_EXPLOITABLE`
- Scores by severity using heuristics: RIP control, poison pointers, heap corruption, /GS canary, stack overflow, write/read AV patterns, high-value modules
- Batch-analyzes whole directories
- Generates JSON, CSV, Markdown, and HTML reports

## Classification

| Verdict | Meaning |
|---|---|
| `EXPLOITABLE` | Attacker can likely control execution |
| `PROBABLY_EXPLOITABLE` | Memory corruption with a plausible path to control |
| `UNKNOWN` | Insufficient signal to classify |
| `NOT_EXPLOITABLE` | Benign (null deref, arithmetic exception) |

## Rules

| Rule | Trigger | Weight |
|---|---|---|
| `rip-control` | RIP equals faulting address | +50 |
| `poison-ptr` | faulting address matches `0x41414141...` pattern | +45 |
| `heap-corruption` | `STATUS_HEAP_CORRUPTION` (0xC0000374) | +45 |
| `rip-non-canonical` | RIP outside any valid canonical range | +40 |
| `stack-overflow` | `STATUS_STACK_OVERFLOW` (0xC00000FD) | +35 |
| `write-av-user` | write AV at user-controlled address | +30 |
| `gs-canary` | `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409) | +30 |
| `write-av-kernel` | write AV at kernel address | +25 |
| `read-av-user` | read AV at user range | +15 |
| `high-value-module` | fault in a Defender/parser/JS engine module | +10 |

Score bands: `90+` critical, `60–89` high, `30–59` medium, `10–29` low, `0–9` ignore.

## Build

### C++ engine

Requires clang or g++ with C++17. No external deps.

```bash
cd engine
clang++ -std=c++17 -O2 -o necropsy-engine.exe \
    src/minidump.cpp src/triage.cpp src/main.cpp \
    -Iinclude -static
