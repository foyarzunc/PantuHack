from modules . toctoc import TocToc
from modules . nmapscan import NmapScan


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
