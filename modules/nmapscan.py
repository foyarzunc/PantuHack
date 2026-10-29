import json
import csv
import nmap


class NmapScan:
    """
    Wrapper de python-nmap para detección de versiones (-sV) y SO (-O).

    Uso:
        ns = NmapScan("192.168.91.246", ports=[22, 80, 443])
        ns.run()                 # ejecuta nmap
        print(ns.summary())      # resumen legible
        print(ns.versions())     # {puerto: {...}}
        print(ns.os_matches())   # [{'name': ..., 'accuracy': ...}]
        ns.to_json("out.json")
    """

    DEFAULT_ARGS = "-sV -O"

    def __init__(self, host, ports=None, sudo=False, timeout=None):
        self.host = host
        self.sudo = sudo
        self.timeout = timeout          # None -> nmap decide
        self.ports = self._normalize_ports(ports) if ports else None
        self._nm = nmap.PortScanner()
        self._result = None             # dict del host tras run()

    # ---------- helpers ----------

    @staticmethod
    def _normalize_ports(ports):
        """Acepta [22, 80] | '22,80,443' | '1-1024' -> string nmap."""
        if isinstance(ports, (list, tuple, set)):
            return ",".join(str(int(p)) for p in sorted(set(ports)))
        return str(ports)

    def _build_arguments(self, extra=None):
        args = self.DEFAULT_ARGS
        if extra:
            args = f"{args} {extra}"
        return args

    # ---------- ejecución ----------

    def run(self, arguments=None, extra=None):
        """Ejecuta nmap. `arguments` sobreescribe los defaults; `extra` se añade."""
        args = arguments if arguments is not None else self._build_arguments(extra)
        kwargs = {"hosts": self.host, "arguments": args, "sudo": self.sudo}
        if self.ports:
            kwargs["ports"] = self.ports
        if self.timeout:
            kwargs["timeout"] = self.timeout

        self._nm.scan(**kwargs)
        self._result = self._nm[self.host] if self.host in self._nm.all_hosts() else None
        return self

    # ---------- parseo ----------

    def _ensure_run(self):
        if self._result is None:
            raise RuntimeError("Llama a .run() antes de consultar resultados")

    def versions(self, proto="tcp"):
        """{puerto: {name, product, version, extrainfo, state}}"""
        self._ensure_run()
        if proto not in self._result:
            return {}
        out = {}
        for port, info in self._result[proto].items():
            if info.get("state") != "open":
                continue
            out[port] = {
                "name": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "extrainfo": info.get("extrainfo", ""),
                "state": info.get("state", ""),
            }
        return out

    def os_matches(self):
        """[{'name': str, 'accuracy': int, 'line': str}] ordenado por accuracy."""
        self._ensure_run()
        matches = self._result.get("osmatch", []) if isinstance(self._result, dict) else []
        return sorted(
            (
                {"name": m.get("name", ""), "accuracy": int(m.get("accuracy", 0)),
                 "line": m.get("line", "")}
                for m in matches
            ),
            key=lambda x: x["accuracy"],
            reverse=True,
        )

    def command_line(self):
        return self._nm.command_line()

    # ---------- exportación ----------

    def to_dict(self):
        self._ensure_run()
        return {
            "host": self.host,
            "state": self._result.get("status", {}).get("state") if self._result else None,
            "command": self.command_line(),
            "tcp": self.versions("tcp"),
            "udp": self.versions("udp"),
            "os": self.os_matches(),
        }

    def to_json(self, path=None):
        data = self.to_dict()
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        return json.dumps(data, indent=2, ensure_ascii=False)

    def to_csv(self, path):
        """CSV plano: proto,puerto,nombre,producto,version,extrainfo"""
        self._ensure_run()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["proto", "puerto", "nombre", "producto", "version", "extrainfo"])
            for proto in ("tcp", "udp"):
                for port, info in self.versions(proto).items():
                    w.writerow([proto, port, info["name"], info["product"],
                                info["version"], info["extrainfo"]])

    # ---------- resumen legible ----------

    def summary(self):
        self._ensure_run()
        if not self._result:
            return f"[!] Host {self.host} sin resultados (¿está up? prueba -Pn)"

        lineas = [f"Host: {self.host}  |  {self.command_line()}"]
        os_list = self.os_matches()
        if os_list:
            top = os_list[0]
            lineas.append(f"SO: {top['name']} ({top['accuracy']}%)")
        else:
            lineas.append("SO: no detectado (¿root/sudo?)")

        tcp = self.versions("tcp")
        if tcp:
            lineas.append("Puertos TCP:")
            for p, info in sorted(tcp.items()):
                desc = " ".join(x for x in (info["product"], info["version"]) if x) or info["name"] or "?"
                lineas.append(f"  {p}/tcp  {desc}")
        else:
            lineas.append("Puertos TCP: (ninguno abierto en los puertos dados)")

        return "\n".join(lineas)