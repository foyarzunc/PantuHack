import socket
import concurrent.futures
import resource


class TocToc:
    """
    Escáner simple de puertos TCP/UDP.

    - TCP: 'open' = connect_ex() == 0 (fiable).
    - UDP: 'open' = se recibió respuesta del servicio (fiable).
           Sin respuesta -> 'open|filtered' (no se cuenta como abierto).

    Flag fast=True:
      - timeouts: TCP 0.5s / UDP 0.3s
      - max_workers: 1000
      - aviso si ulimit -n < workers*2
      - si protocol incluye UDP y no se pasaron ports -> usa TOP_UDP_PORTS para UDP
    """

    VALID_PROTOCOLS = ('tcp', 'udp', 'both')

    # Top-100 UDP típicos (servicios que de verdad responden)
    TOP_UDP_PORTS = [
        53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 177, 389, 427, 443, 445,
        500, 514, 515, 520, 623, 631, 996, 997, 998, 999, 1022, 1023,
        1025, 1026, 1027, 1028, 1029, 1030, 1194, 1434, 1645, 1646,
        1701, 1718, 1719, 1812, 1813, 1900, 2049, 2222, 3283, 3389,
        3456, 3703, 4500, 5000, 5001, 5060, 5061, 5353, 5355, 5432,
        5632, 6000, 6001, 8610, 8611, 8612, 8613, 8614, 9000, 9001,
        9040, 9050, 9060, 9080, 9090, 9100, 9200, 9300, 9876, 9877,
        9878, 9879, 9880, 9881, 9882, 9883, 9884, 9885, 9886, 9887,
        9888, 9889, 9890, 9891, 9892, 9893, 9894, 9895, 9896, 9897,
        9898, 9899, 9900, 9987, 10000, 11211, 17185, 20031, 27015,
        27016, 27017, 30718, 31337, 32768, 32769, 32770, 32771,
    ]

    def __init__(self, host, **args):
        self.host = host
        self.fast = bool(args.get('fast', False))

        # --- timeouts ---
        default_timeout = 2.0
        default_fast_timeout = {'tcp': 0.5, 'udp': 0.3}
        self._timeouts = {
            'tcp': args.get('timeout', None) or (
                default_fast_timeout['tcp'] if self.fast else default_timeout
            ),
            'udp': args.get('timeout', None) or (
                default_fast_timeout['udp'] if self.fast else default_timeout
            ),
        }
        # Compat: self.timeout refleja TCP (por si algo externo lo consulta)
        self.timeout = self._timeouts['tcp']

        # --- workers ---
        self.max_workers = args.get('max_workers', 1000 if self.fast else 300)

        # --- protocolo ---
        self.protocol = (args.get('protocol') or 'both').lower()
        if self.protocol not in self.VALID_PROTOCOLS:
            raise ValueError(f"protocol inválido: {self.protocol!r} (usa {self.VALID_PROTOCOLS})")

        # --- puertos (por protocolo) ---
        ports_arg = args.get('ports', None)
        self._ports_explicit = ports_arg is not None

        if self._ports_explicit:
            puertos = self.parse_ports(ports_arg)
            self.ports = {'tcp': puertos, 'udp': puertos}
        else:
            full = list(range(1, 65536))
            if self.fast and self.protocol in ('udp', 'both'):
                # UDP -> top; TCP -> full
                self.ports = {
                    'tcp': full,
                    'udp': sorted(set(self.TOP_UDP_PORTS)),
                }
            else:
                self.ports = {'tcp': full, 'udp': full}

        # --- payload UDP ---
        self.udp_payload = args.get('udp_payload', b"\x00")

        # --- chequeo de ulimit ---
        self._ulimit_warning = self._check_ulimit()

    # ---------- helpers ----------

    def parse_ports(self, arg):
        if isinstance(arg, (list, tuple, set)):
            return sorted(set(int(p) for p in arg))
        if not arg:
            return list(range(1, 65536))
        ports = []
        for parte in arg.split(","):
            parte = parte.strip()
            if not parte:
                continue
            if "-" in parte:
                a, b = parte.split("-")
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(parte))
        return sorted(set(ports))

    def _check_ulimit(self):
        """Devuelve warning string si el soft limit de FDs es bajo, o None."""
        try:
            soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        except Exception:
            return None
        needed = self.max_workers * 2
        if soft != resource.RLIM_INFINITY and soft < needed:
            return (
                f"[!] ulimit -n = {soft} < {needed} (workers*2). "
                f"Ejecuta: ulimit -n {needed}  (o sube max_workers más bajo)"
            )
        return None

    # ---------- checks (devuelven estado) ----------

    def check_tcp(self, port):
        """Devuelve 'open' | 'closed' | 'filtered'."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeouts['tcp'])
        try:
            r = s.connect_ex((self.host, port))
            if r == 0:
                return 'open'
            return 'closed' if r in (111, 10061) else 'filtered'
        except socket.timeout:
            return 'filtered'
        except OSError:
            return 'filtered'
        finally:
            s.close()

    def check_udp(self, port):
        """Devuelve 'open' | 'open|filtered' | 'closed'."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self._timeouts['udp'])
        try:
            s.sendto(self.udp_payload, (self.host, port))
            try:
                s.recvfrom(1024)
                return 'open'
            except socket.timeout:
                return 'open|filtered'
            except ConnectionRefusedError:
                return 'closed'
        except ConnectionRefusedError:
            return 'closed'
        except OSError:
            return 'filtered'
        finally:
            s.close()

    # ---------- motor de escaneo ----------

    def _scan(self, proto, only_open=True):
        checker = self.check_tcp if proto == "tcp" else self.check_udp
        ports = self.ports[proto]
        resultados = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futuros = {ex.submit(checker, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futuros):
                port = futuros[fut]
                try:
                    resultados[port] = fut.result()
                except Exception:
                    resultados[port] = 'error'

        if only_open:
            return sorted(p for p, st in resultados.items() if st == 'open')
        return dict(sorted(resultados.items()))

    # ---------- API pública ----------

    def scan(self, proto=None, only_open=True):
        proto = (proto if proto is not None else self.protocol).lower()
        if proto == 'both':
            return {
                'tcp': self._scan('tcp', only_open=only_open),
                'udp': self._scan('udp', only_open=only_open),
            }
        if proto not in ('tcp', 'udp'):
            raise ValueError(f"Protocolo inválido: {proto!r} (usa 'tcp', 'udp' o 'both')")
        return self._scan(proto, only_open=only_open)

    def scan_all(self, only_open=True):
        return {
            'tcp': self._scan('tcp', only_open=only_open),
            'udp': self._scan('udp', only_open=only_open),
        }

    # ---------- info ----------

    def info(self):
        """Resumen de la configuración efectiva (útil para debug)."""
        lineas = [
            f"Host        : {self.host}",
            f"Fast        : {self.fast}",
            f"Protocol    : {self.protocol}",
            f"Timeout TCP : {self._timeouts['tcp']}s",
            f"Timeout UDP : {self._timeouts['udp']}s",
            f"Workers     : {self.max_workers}",
            f"Puertos TCP : {len(self.ports['tcp'])}",
            f"Puertos UDP : {len(self.ports['udp'])}",
        ]
        if self._ulimit_warning:
            lineas.append(self._ulimit_warning)
        return "\n".join(lineas)