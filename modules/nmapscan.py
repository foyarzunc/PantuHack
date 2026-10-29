import json
import csv
import nmap


class NmapScan:
    """
    python-nmap wrapper for version detection (-sV) and OS detection (-O).

    Usage:
        ns = NmapScan("192.168.91.246", ports=[22, 80, 443])
        ns.run()                 # runs nmap
        print(ns.summary())      # human-readable summary
        print(ns.versions())     # {port: {...}}
        print(ns.os_matches())   # [{'name': ..., 'accuracy': ...}]
        ns.to_json("out.json")
    """

    DEFAULT_ARGS = "-sV -O"

    def __init__(self, host, ports=None, sudo=False, timeout=None):
        self.host = host
        self.sudo = sudo
        self.timeout = timeout          # None -> let nmap decide
        self.ports = self._normalize_ports(ports) if ports else None
        self._nm = nmap.PortScanner()
        self._result = None             # host dict after run()

    # ---------- helpers ----------

    @staticmethod
    def _normalize_ports(ports):
        """Accepts [22, 80] | '22,80,443' | '1-1024' -> nmap string."""
        if isinstance(ports, (list, tuple, set)):
            return ",".join(str(int(p)) for p in sorted(set(ports)))
        return str(ports)

    def _build_arguments(self, extra=None):
        args = self.DEFAULT_ARGS
        if extra:
            args = f"{args} {extra}"
        return args

    # ---------- execution ----------

    def run(self, arguments=None, extra=None):
        """Runs nmap. `arguments` overrides the defaults; `extra` is appended."""
        args = arguments if arguments is not None else self._build_arguments(extra)
        kwargs = {"hosts": self.host, "arguments": args, "sudo": self.sudo}
        if self.ports:
            kwargs["ports"] = self.ports
        if self.timeout:
            kwargs["timeout"] = self.timeout

        self._nm.scan(**kwargs)
        self._result = self._nm[self.host] if self.host in self._nm.all_hosts() else None
        return self

    # ---------- parsing ----------

    def _ensure_run(self):
        if self._result is None:
            raise RuntimeError("Call .run() before querying results")

    def versions(self, proto="tcp"):
        """{port: {name, product, version, extrainfo, state}}"""
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
        """[{'name': str, 'accuracy': int, 'line': str}] sorted by accuracy."""
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

    # ---------- export ----------

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
        """Flat CSV: proto,port,name,product,version,extrainfo"""
        self._ensure_run()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["proto", "port", "name", "product", "version", "extrainfo"])
            for proto in ("tcp", "udp"):
                for port, info in self.versions(proto).items():
                    w.writerow([proto, port, info["name"], info["product"],
                                info["version"], info["extrainfo"]])

    # ---------- human-readable summary ----------

    def summary(self):
        self._ensure_run()
        if not self._result:
            return f"[!] Host {self.host} has no results (is it up? try -Pn)"

        lines = [f"Host: {self.host}  |  {self.command_line()}"]
        os_list = self.os_matches()
        if os_list:
            top = os_list[0]
            lines.append(f"OS: {top['name']} ({top['accuracy']}%)")
        else:
            lines.append("OS: not detected (root/sudo?)")

        tcp = self.versions("tcp")
        if tcp:
            lines.append("TCP ports:")
            for p, info in sorted(tcp.items()):
                desc = " ".join(x for x in (info["product"], info["version"]) if x) or info["name"] or "?"
                lines.append(f"  {p}/tcp  {desc}")
        else:
            lines.append("TCP ports: (none open among the given ports)")

        return "\n".join(lines)