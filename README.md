# ByteWall

**AI-assisted security scan orchestrator, built for personal bug bounty use.**

ByteWall coordinates well-established open-source security tools (Nmap, Nuclei, and others), normalizes their output into a single data model, and uses a local LLM (via Ollama) to help prioritize and summarize findings. It's not a scanner engine written from scratch — it's an orchestration and analysis layer on top of proven tools, built for my own authorized testing workflow.

This is a personal project, not a product. It's not meant to be installed and run by others — this repo exists mainly as a public record of the architecture and design decisions behind it.

---

## Why this exists

Most scanners hand you raw output and leave the interpretation to you. ByteWall's goal is to go one step further: normalize findings from multiple tools into a consistent format, then use a local model to help triage what actually matters, in plain language, without sending any data to a third-party API.

---

## Scope safety — the core design principle

This project is built around one non-negotiable rule: **a target is never scanned unless it has been explicitly whitelisted.**

- Every scan run is checked against a program-specific scope file (`in_scope` / `out_of_scope` patterns, domains, wildcards, and CIDR ranges).
- `out_of_scope` always wins, even if a target also matches an `in_scope` pattern.
- Anything not explicitly listed is rejected by default — this is a whitelist model, not a blacklist.
- The scope engine (`core/scope_manager.py`) is fully unit-tested; see `tests/unit/test_scope_manager.py`.
- No target data, scope files, or scan results are ever committed to this repository (`data/` is gitignored).

This exists to make sure the tool can never accidentally scan something outside an authorized bug bounty program.

---

## What's public vs. what's kept private

This repository contains the orchestration architecture, data normalization layer, AI analysis layer, and reporting logic — the parts that are useful to share and don't carry misuse risk.

Some active-scanning modules (the parts that would let someone point this at an arbitrary target and get exploit-ready output) are intentionally kept out of this repo. This isn't about hiding poor code — it's a deliberate choice, for a few reasons:

- Reducing the risk of this tooling being repurposed for unauthorized scanning.
- Staying consistent with responsible disclosure practices.
- Keeping some of the tuning I rely on in my own bug bounty work private.

What's here is enough to understand and evaluate the architecture, even without the private pieces.

---

## Architecture

```
targets
   -> ScopeManager.filter_targets()     # whitelist check, default-deny
   -> in-scope targets only
   -> modules/*Runner.run()             # Nmap, Nuclei, etc. (some private)
   -> parsers/*_parser.py               # raw tool output -> common Finding schema
   -> ai/analyzer.py                    # local LLM triage + summarization
   -> reports/*_builder.py              # HTML / Markdown report
```

Every scanning module implements a shared `BaseRunner` interface (`modules/base_runner.py`), so adding a new tool doesn't require touching the orchestrator. Every parser converts tool-specific output into one common `Finding` model (`parsers/schema.py`), so the AI and reporting layers never need to know which tool a result came from.

---

## Tech stack

| Layer | Technology |
|---|---|
| Orchestration | Python 3.11+ |
| Data validation | Pydantic |
| Scope config | YAML |
| AI / LLM | Ollama (local, e.g. Llama 3) — no data leaves the machine |
| Scanning tools | Nmap, Nuclei (community templates), others planned |
| Testing | pytest |

---

## Project structure

```
bytewall/
├── core/                 # orchestrator, config, scope manager
├── modules/              # per-tool runners (some private)
│   ├── recon/
│   └── webscan/
├── parsers/              # raw tool output -> common Finding schema
├── ai/                   # local LLM client + analysis/prioritization
├── reports/              # HTML/Markdown report generation
├── data/                 # scope files, scan results, logs — gitignored
├── tests/
└── docs/
```

---

## Status

Early stage, actively being built out module by module. This is a work-in-progress personal tool, evolving as I use it in real bug bounty engagements.

## Legal

This tool is intended exclusively for use on systems I am explicitly authorized to test, within the scope of programs I'm enrolled in. The scope-checking logic in this repository is a safeguard, not a substitute for reading and following each program's actual rules.

## License

Proprietary — all rights reserved.