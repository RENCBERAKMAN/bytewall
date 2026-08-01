# ByteWall

**A scope-safe, AI-assisted security scan orchestrator.**

ByteWall coordinates well-established open-source security tools (Nmap, Nuclei) into a single pipeline, normalizes their output into one common data model, and uses a locally-running LLM (via [Ollama](https://ollama.com)) to help prioritize and summarize findings — entirely offline, with no data sent to any third-party API.

It started as a personal tool for authorized bug bounty testing. It's fully open source: read the code, run it, fork it, open a PR if you find a bug or want to add a tool.

---

## Why this exists

Most scanners hand you raw output and leave the interpretation to you. ByteWall goes one step further: it normalizes findings from multiple tools into a consistent format, then uses a local model to help triage what actually matters — in plain language, without leaking any scan data outside your machine.

---

## Scope safety — the core design principle

This project is built around one non-negotiable rule: **a target is never scanned unless it has been explicitly whitelisted.**

- Every scan run is checked against a program-specific scope file (`in_scope` / `out_of_scope` patterns — exact domains, wildcards, and CIDR ranges are all supported).
- `out_of_scope` always wins, even if a target also matches an `in_scope` pattern.
- Anything not explicitly listed is rejected by default — this is a **whitelist model**, not a blacklist. If you forget to list something, it gets rejected, not scanned.
- The scope engine (`core/scope_manager.py`) is fully unit-tested; see `tests/unit/test_scope_manager.py`.

### How scope is selected — manual, on purpose

There is no automatic scope discovery. **You** create a YAML file describing exactly what a given program allows, and ByteWall only ever scans against that file. Nothing is inferred, guessed, or auto-expanded.

```yaml
# data/scope/my_program.yaml
program_name: "example_program"

in_scope:
  - "*.example.com"
  - "api.example.com"
  - "203.0.113.0/24"

out_of_scope:
  - "blog.example.com"   # third-party hosted, explicitly excluded
  - "internal.example.com"

notes: >
  Link to the program's official scope page here.
  When in doubt, don't scan — check the program's rules first.
```

Before any real scan, always run with `--dry-run` first — it shows exactly which targets would be scanned without touching anything, so you can visually confirm the filtering is correct.

---

## Architecture

```
targets
   -> ScopeManager.filter_targets()     # whitelist check, default-deny
   -> in-scope targets only
   -> modules/*Runner.run()             # Nmap, Nuclei (subprocess, no shell=True)
   -> parsers/*_parser.py               # raw tool output -> common Finding schema
   -> ai/analyzer.py                    # local LLM triage + summarization (Ollama)
   -> reports/html_builder.py           # HTML report
```

Every scanning module implements a shared `BaseRunner` interface (`modules/base_runner.py`), so adding a new tool doesn't require touching the orchestrator. Every parser converts tool-specific output into one common `Finding` model (`parsers/schema.py`), so the AI and reporting layers never need to know which tool a result came from. All subprocess calls use argument lists (never `shell=True`), which eliminates shell-injection risk regardless of what a target string contains.

The AI layer never overrides a tool's severity rating — it only adds a plain-language summary and flags likely false positives. Prioritization sorts by severity first, then pushes flagged false positives toward the bottom, without ever deleting a finding.

---

## Tech stack

| Layer | Technology |
|---|---|
| Orchestration | Python 3.11+ |
| Data validation | Pydantic |
| Scope config | YAML |
| AI / LLM | Ollama (local, e.g. Llama 3) — nothing leaves the machine |
| Recon | Nmap |
| Vulnerability scanning | Nuclei (community templates) |
| Reporting | Jinja2 (HTML report generation) |
| Testing | pytest (mocked subprocess/HTTP calls, no live network required) |

---

## Project structure

```
bytewall/
├── core/                     # orchestrator, config, scope manager
├── modules/
│   ├── base_runner.py        # shared interface every tool runner implements
│   ├── recon/
│   │   └── nmap_runner.py
│   └── webscan/
│       └── nuclei_runner.py
├── parsers/                   # raw tool output -> common Finding schema
├── ai/
│   ├── ollama_client.py       # local LLM HTTP client
│   ├── analyzer.py            # summarization, false-positive triage, priority sort
│   └── prompts/
├── reports/
│   ├── html_builder.py
│   └── templates/
├── data/
│   ├── scope/                 # your scope files live here (gitignored except the example)
│   └── reports/                # generated reports land here (gitignored)
├── tests/
│   └── unit/                   # 80+ tests, all run against mocked subprocess/HTTP calls
└── docs/
```

---

## Setup

```bash
git clone https://github.com/<your-username>/bytewall.git
cd bytewall

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### External tools (installed separately, not bundled)

| Tool | Install |
|---|---|
| Nmap | [nmap.org/download](https://nmap.org/download.html) |
| Nuclei | [github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases), then `nuclei -update-templates` |
| Ollama | [ollama.com/download](https://ollama.com/download), then `ollama pull llama3` |

### Configure your scope

```bash
cp data/scope/program.example.yaml data/scope/my_program.yaml
# edit my_program.yaml with the real in_scope / out_of_scope rules
# for a program you are actually authorized to test
```

### Run

```bash
# always dry-run first — verify exactly what would be scanned
python main.py --program my_program --target api.example.com --dry-run

# scan with both tools, print results to the terminal
python main.py --program my_program --target api.example.com --tools nmap,nuclei

# full pipeline: scan + local AI triage + HTML report
python main.py --program my_program --target api.example.com --ai --report data/reports/scan.html
```

**Flags:**

| Flag | Description |
|---|---|
| `--program` | Name of the YAML file under `data/scope/` (without extension) |
| `--target` | Target to scan; repeat the flag for multiple targets |
| `--tools` | Comma-separated list of tools to run (default: `nmap,nuclei`) |
| `--nmap-profile` | `quick` / `standard` / `aggressive` |
| `--nuclei-profile` | `quick` / `standard` / `aggressive` (maps to severity filters) |
| `--dry-run` | Show what would be scanned without running anything |
| `--ai` | Run findings through the local Ollama model for summary + false-positive triage |
| `--report PATH` | Write results to an HTML report at the given path |

### Tests

```bash
pytest tests/unit -v
```

All tests run against mocked subprocess/HTTP calls — no live network access or installed tools required to run the test suite.

---

## Contributing

Issues and PRs are welcome — bug fixes, new tool runners (following the `BaseRunner` interface), parser improvements, better prompts for the AI layer, a Markdown report option, whatever. If you're adding a new scanning module, please keep the scope-safety guarantee intact: nothing should ever reach a runner without going through `ScopeManager` first, and please add tests alongside any new logic.

---

## Legal / acceptable use

This tool is intended exclusively for use on systems you are explicitly authorized to test — for example, within the scope of a bug bounty program you're enrolled in. Scanning systems without authorization may be illegal in your jurisdiction. The scope-checking logic in this repository is a safeguard against accidental misuse, not a substitute for reading and following each program's actual rules. You are responsible for how you use this tool.

## License

MIT — see [LICENSE](LICENSE).