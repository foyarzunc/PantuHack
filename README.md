# PantuHack

> ⚠️ **Early beta.** APIs, CLI flags and module names may change without notice. Not production-ready.

PantuHack is a lightweight Python toolkit for network reconnaissance and vulnerability research during authorized penetration testing engagements. It chains together port scanning, service/OS fingerprinting, and local exploit lookup into a single workflow.

## What it does

- **Port scanning** (`modules/toctoc.py`) — fast, pure-Python TCP/UDP port scanner. Reports which ports are open in a given range, nothing more.
- **Service & OS fingerprinting** (`modules/nmapscan.py`) — wraps `python-nmap` to run `-sV -O` against the ports found open, extracting product, version and OS matches.
- **Exploit lookup** (`vendors/ExploitDB.py`) — cross-references detected service/version pairs against a local [Exploit-DB](https://www.exploit-db.com/) copy via `searchsploit`, returning matching exploit titles and their official exploit-db.com links.

## How it fits together

```
TocToc (port scan)
   └── open ports
        └── NmapScan (-sV -O)
             └── product/version per port
                  └── ExploitDB.search(product, version)
                       └── matching exploits + official links
```

## Requirements

- Python 3.11+
- `nmap` installed on the system, with `sudo` privileges for OS detection (`-O`)
- `git` (used to auto-clone the local Exploit-DB copy on first run)
- Python packages: `python-nmap`, `python-dotenv`

```bash
pip install python-nmap python-dotenv
```

## Exploit-DB setup

You don't need to install `searchsploit` by hand. On first run, `ExploitDB.ensure_binary()`:

1. Looks for `SEARCHSPLOIT_BIN` in `.env`.
2. Falls back to `searchsploit` on the system `PATH`.
3. If neither exists, clones [exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb) into `vendor/exploitdb/` inside the project and saves the resolved path to `.env`.

The database itself is updated with:

```python
edb.update()  # runs `searchsploit -u`
```

and can optionally be scheduled via cron (`edb.setup_cron()`), prompted automatically the first time the repo is cloned locally.

## Usage

```python
from modules.toctoc import TocToc
from modules.nmapscan import NmapScan
from vendors.ExploitDB import ExploitDB

host = "192.168.1.205"

toctoc = TocToc(host, fast=True, protocol="tcp", ports="1-20000")
ports = toctoc.scan()

if ports:
    ns = NmapScan(host, ports=ports, sudo=True)
    ns.run()
    print(ns.summary())

    edb = ExploitDB()
    edb.ensure_binary()

    for port, info in ns.versions().items():
        if not info["version"]:
            continue
        for hit in edb.search(info["product"], info["version"]):
            print(f"[{port}] {hit['title']} -> {hit['official_url']}")
```

Or just run the orchestrator directly:

```bash
python PantuHack.py
```

## Configuration

Copy `.env.example` to `.env` and adjust as needed:

```
SEARCHSPLOIT_BIN=
```

Leave it empty to let PantuHack resolve/clone the binary automatically on first run.

## Roadmap

- [ ] Combined JSON/CSV report (ports + fingerprint + suggested exploits)
- [ ] CPE/CVE-based matching as an alternative to free-text `searchsploit` queries, to reduce false positives
- [ ] CLI entry point (currently a single script with a hardcoded target)
- [ ] Expand the product-name normalization table beyond `Apache httpd`

## Legal / ethical use

PantuHack performs active scanning and queries a local exploit database. **Only use it against systems you own or are explicitly authorized to test.** Unauthorized scanning or exploitation of systems you don't have permission to test may be illegal in your jurisdiction. The author assumes no responsibility for misuse.

## License

[MIT](LICENSE)
