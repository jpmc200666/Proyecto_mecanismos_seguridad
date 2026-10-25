import os
import subprocess
import time

from common import VICTIM_IP

DEVNULL = subprocess.DEVNULL

ATTACK_CMDS = {
    "syn_flood": lambda us: f"hping3 -q -S -p 80 -i u{us} {VICTIM_IP}",
    "udp_flood": lambda us: f"hping3 -q --udp -p 9 -d 200 -i u{us} {VICTIM_IP}",
    "icmp_flood": lambda us: f"hping3 -q --icmp -d 64 -i u{us} {VICTIM_IP}",
}

RAMP_US = [50000, 10000, 2000, 500]


def start_services(net, workdir):
    www = os.path.join(workdir, "www")
    os.makedirs(www, exist_ok=True)
    blob = os.path.join(www, "file.bin")
    if not os.path.exists(blob):
        with open(blob, "wb") as f:
            f.write(os.urandom(500 * 1024))
    h1 = net.get("h1")
    return [h1.popen(["python3", "-m", "http.server", "80"], cwd=www, stdout=DEVNULL, stderr=DEVNULL),
            h1.popen(["iperf3", "-s"], stdout=DEVNULL, stderr=DEVNULL)]


def start_normal_traffic(net, with_ping=True):
    h2, h4 = net.get("h2"), net.get("h4")
    web = (f"while true; do curl -s -m 5 -o /dev/null http://{VICTIM_IP}/file.bin; "
           f"sleep 0.$((RANDOM%9+1)); done")
    iperf = (f"while true; do iperf3 -c {VICTIM_IP} -u -b $((RANDOM%3+1))M -t 4 >/dev/null 2>&1; sleep 1; "
             f"iperf3 -c {VICTIM_IP} -b 2M -t 3 >/dev/null 2>&1; sleep 1; done")
    procs = [h2.popen(["bash", "-c", web], stdout=DEVNULL, stderr=DEVNULL),
             h4.popen(["bash", "-c", iperf], stdout=DEVNULL, stderr=DEVNULL)]
    if with_ping:
        procs.append(h2.popen(["ping", "-i", "0.2", VICTIM_IP], stdout=DEVNULL, stderr=DEVNULL))
    return procs


def attack_duration(stage_s, hold_s):
    return stage_s * len(RAMP_US) + hold_s


def run_attack(net, kind, final_us=100, stage_s=2, hold_s=20):
    """Ataque con escalada gradual y fase sostenida. Bloquea hasta terminar.
    Devuelve (inicio, fin) como tiempo epoch."""
    h3 = net.get("h3")
    t0 = time.time()
    for us in RAMP_US:
        h3.cmd(f"timeout {stage_s} {ATTACK_CMDS[kind](us)} >/dev/null 2>&1")
    h3.cmd(f"timeout {hold_s} {ATTACK_CMDS[kind](final_us)} >/dev/null 2>&1")
    return t0, time.time()


def stop_procs(procs):
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    subprocess.run(["pkill", "-f", "curl -s|iperf3 -c|hping3"], stdout=DEVNULL, stderr=DEVNULL)


def stop_services(procs):
    stop_procs(procs)
    subprocess.run(["pkill", "-f", "http.server|iperf3 -s"], stdout=DEVNULL, stderr=DEVNULL)
