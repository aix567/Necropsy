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

## C++ engine

Requires clang or g++ with C++17. No external deps.

```bash
cd engine
clang++ -std=c++17 -O2 -o necropsy-engine.exe \
    src/minidump.cpp src/triage.cpp src/main.cpp \
    -Iinclude -static

```
## C# GUI

Requires .NET 8 SDK.
bash

cd gui
dotnet build -c Release

The GUI searches for necropsy-engine.exe next to itself. Copy it over:
bash

cp ../engine/necropsy-engine.exe bin/Release/net8.0-windows/

Python orchestrator

Requires Python 3.10+. Stdlib only.
bash

PYTHONPATH=. python -m pynecropsy --help

Usage
C++ engine (single dump)
bash

./necropsy-engine.exe path/to/crash.dmp
./necropsy-engine.exe path/to/crash.dmp --json

## C# GUI

Double-click necropsy-gui.exe or run dotnet run -c Release.

Drag .dmp files in, click Analyze all.
Python (batch + reports)
bash

PYTHONPATH=. python -m pynecropsy batch ./dumps -o ./triage_out -j 4

<img width="1880" height="1055" alt="screenshot 1" src="https://github.com/user-attachments/assets/07f84334-44e2-4f5c-8948-3490b9b4b7c2" />
<img width="1816" height="1067" alt="screenshot 3" src="https://github.com/user-attachments/assets/31b2c57b-3af5-4503-8e9f-0c568fc67169" />
<img width="1891" height="1036" alt="screenshot 2" src="https://github.com/user-attachments/assets/72e341d5-261d-4bbc-9324-1e4192bb985d" />


Writes triage.json, triage.csv, triage.md, triage.html to the output directory.
Example
text

[+] C:/dumps/crasher.dmp
    size: 26802113 bytes
    processor: x64, 12 cores
    os: 10.0.26100
    modules: 18

[*] exception
    code:     0xc0000005 (ACCESS_VIOLATION)
    access:   WRITE
    address:  0x41414141

[*] registers
    rip  0x00007ff660f01560
    rsp  0x000000372770f820
    rax  0x0000000041414141

[*] verdict: EXPLOITABLE (score 75)
    module: crasher.exe
    frame:  crasher.exe+0x1560

[*] findings
    [critical] poison-ptr     faulting address matches poison pattern
    [high]     write-av-user  write AV at user-controlled address

Limitations

    x64 only. No x86 or ARM64 register parsing.

    Heuristics, not proof. EXPLOITABLE means "worth a look," not "confirmed exploitable."

    No symbol resolution. Module+offset only. Wire dbghelp.dll for PDB lookup.

    Reads the minidump only. No live-process attach.

Roadmap

    □

    x86 register parsing
    □

    PDB symbol resolution via dbghelp.dll
    □

    Memory stream inspection (read faulting memory, check byte patterns)
    □

    Stack unwind for return-address inspection
    □

    HTML report with per-dump detail pages
    □

    WinAFL output-directory watcher (auto-triage as fuzzer produces crashes)

Disclaimer

For security research, DFIR, and crash analysis on systems you own or have authorization to test. Report vulnerabilities responsibly. Not a vulnerability scanner and not a fuzzer — this tool triages crashes that already exist.
