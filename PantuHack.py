from modules . toctoc import TocToc
from modules . nmapscan import NmapScan
from vendors . ExploitDB import ExploitDB

host = "192.168.91.246"

toctoc = TocToc(host, fast=True, protocol="tcp", ports="22,80-139")
ports = toctoc.scan()


if not ports:
    print("No TCP opens...")
else:
    ns = NmapScan(host, ports=ports, sudo=True)
    ns.run()                                   # -sV -O por defecto
    print(ns.summary())

    # 3. Exportar
    #ns.to_json("reporte.json")
    #ns.to_csv("reporte.csv")

    # 4. Acceso programático
    print(ns.versions())
    print(ns.os_matches())
    edb = ExploitDB()
    edb.ensure_binary()

    for port, info in ns.versions().items():
        if not info['product']:
            continue
        find = edb.buscar(info['product'], info['version'])
        if find:
            if len(info['version']) <= 0:
                print(f"  [*] No info for {info['product']} missed versions...")
                continue
            print(f"\n[{port}] {info['product']} {info['version']}")
            for h in find:
                print(f"   - {h['titulo']}  ->  {h['url_oficial']}")
