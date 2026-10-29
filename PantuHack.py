import re

from modules . toctoc import TocToc
from modules . nmapscan import NmapScan
from vendors . ExploitDB import ExploitDB


# Known noise that nmap adds to the "product" field, worth cleaning up
# before searching exploitdb. NOTE: each pattern is anchored (^...$) and
# targets one specific product, never a generic substring like "ftpd"
# or "httpd" on their own — that would break legitimate names such as
# ProFTPD, PureFTPd or vsftpd, which NEED their full name to match
# entries in the exploitdb catalog.
_KNOWN_NOISE = {
    re.compile(r"^Apache httpd$", re.IGNORECASE): "Apache",
}


def normalize_product(product: str) -> str:
    """Cleans up known noise from nmap's product field without touching
    legitimate product names (e.g. must not affect vsftpd, ProFTPD, PureFTPd)."""
    for pattern, replacement in _KNOWN_NOISE.items():
        if pattern.match(product):
            return replacement
    return product


host = "192.168.1.205"

toctoc = TocToc(host, fast=True, protocol="tcp", ports="1-20000")
ports = toctoc.scan()


if not ports:
    print("No TCP opens...")
else:
    ns = NmapScan(host, ports=ports, sudo=True)
    ns.run()                                   # -sV -O by default
    print(ns.summary())

    # 3. Export
    #ns.to_json("report.json")
    #ns.to_csv("report.csv")

    edb = ExploitDB()
    edb.ensure_binary()

    os_details = ns.os_matches()
    if os_details:
        print(f"OS DETAILS {os_details[0]['name']}, accuracy {os_details[0]['accuracy']}%")

    for port, info in ns.versions().items():
        product = normalize_product(info['product']) if info['product'] else info['name']

        if not info['version']:
            print(f"  [*] No info for {product}, missing version...")
            continue

        findings = edb.search(product, info['version'])
        if findings:
            print(f"\n[{port}] {product} {info['version']}")
            for h in findings:
                print(f"   - {h['title']}  ->  {h['official_url']}")