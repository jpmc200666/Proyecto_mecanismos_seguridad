import collections
import math

VICTIM_IP = "10.0.0.1"          
VICTIM_IFACE = "s1-eth1"        
WINDOW = 1.0                    
CLASSES = ["normal", "syn_flood", "udp_flood", "icmp_flood"]
CLASS_PROTO = {"syn_flood": 6, "udp_flood": 17, "icmp_flood": 1}  

FEATURES = [
    "pkts", "bytes", "avg_len",
    "tcp_frac", "udp_frac", "icmp_frac",
    "syn_pkts", "syn_ratio",
    "unique_src", "src_entropy", "top_src_share", "unique_dport",
]

HISTORY = 5    
HORIZON = 3    

Rec = collections.namedtuple("Rec", "ts src proto length syn dport")

_TSHARK_FIELDS = ["frame.time_epoch", "ip.src", "ip.proto", "frame.len",
                  "tcp.flags", "tcp.dstport", "udp.dstport"]


def _field_args():
    args = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for f in _TSHARK_FIELDS:
        args += ["-e", f]
    return args


def tshark_read_cmd(pcap):
    """Comando para leer un pcap (solo paquetes dirigidos a la víctima)."""
    return ["tshark", "-r", pcap, "-n", "-Y", f"ip.dst=={VICTIM_IP}"] + _field_args()


def tshark_live_cmd(iface):
    """Comando para captura en vivo en la interfaz de la víctima."""
    return ["tshark", "-i", iface, "-f", f"dst host {VICTIM_IP}", "-n", "-l"] + _field_args()


def iter_records(stream):
    """Convierte las líneas de tshark en objetos Rec."""
    for line in stream:
        p = line.rstrip("\n").split("\t")
        if len(p) < 7:
            p += [""] * (7 - len(p))
        try:
            ts = float(p[0])
        except ValueError:
            continue
        proto = int(p[2]) if p[2].isdigit() else 0
        length = int(p[3]) if p[3].isdigit() else 0
        flags = int(p[4], 16) if p[4].startswith("0x") else 0
        syn = (flags & 0x12) == 0x02          # SYN sin ACK
        yield Rec(ts, p[1], proto, length, syn, p[5] or p[6])


class WindowAggregator:
    """Agrupa paquetes en ventanas de tiempo y calcula las características."""

    def __init__(self, window=WINDOW):
        self.window = window
        self.cur = None
        self._reset()

    def _reset(self):
        self.pkts = self.bytes = self.tcp = self.udp = self.icmp = self.syn = 0
        self.src = collections.Counter()
        self.dports = set()

    def _close(self):
        start = self.cur * self.window
        n = self.pkts
        if n == 0:
            feats, top = dict.fromkeys(FEATURES, 0.0), None
        else:
            ent = -sum((c / n) * math.log2(c / n) for c in self.src.values())
            top, topc = self.src.most_common(1)[0]
            feats = {
                "pkts": n, "bytes": self.bytes, "avg_len": self.bytes / n,
                "tcp_frac": self.tcp / n, "udp_frac": self.udp / n, "icmp_frac": self.icmp / n,
                "syn_pkts": self.syn, "syn_ratio": self.syn / self.tcp if self.tcp else 0.0,
                "unique_src": len(self.src), "src_entropy": ent,
                "top_src_share": topc / n, "unique_dport": len(self.dports),
            }
        self._reset()
        return start, feats, top

    def add(self, rec):
        """Agrega un paquete. Devuelve la lista de ventanas que se cerraron."""
        out = []
        w = int(rec.ts // self.window)
        if self.cur is None:
            self.cur = w
        while w > self.cur:
            out.append(self._close())
            self.cur += 1
        self.pkts += 1
        self.bytes += rec.length
        if rec.proto == 6:
            self.tcp += 1
            self.syn += int(rec.syn)
        elif rec.proto == 17:
            self.udp += 1
        elif rec.proto == 1:
            self.icmp += 1
        self.src[rec.src] += 1
        if rec.dport:
            self.dports.add(rec.dport)
        return out
