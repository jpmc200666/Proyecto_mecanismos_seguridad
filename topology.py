import os
import shutil
import socket
import subprocess
import time

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

OF_PORT = 6653
HERE = os.path.dirname(os.path.abspath(__file__))


def build_net(victim_bw=5):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=OF_PORT)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")
    net.addLink(h1, s1, bw=victim_bw, max_queue_size=200)   
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    return net


def start_net(net):
    net.start()
    if hasattr(net, "waitConnected"):
        net.waitConnected(timeout=15)
    else:
        time.sleep(4)
    net.pingAll(timeout="1")     


def _controller_up():
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", OF_PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ensure_controller():
    """Arranca Ryu (learning switch + API REST) si no hay un controlador activo."""
    if _controller_up():
        return None
    if not shutil.which("ryu-manager"):
        raise RuntimeError("ryu-manager no está en el PATH (ver setup.sh)")
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    log = open(os.path.join(HERE, "results", "ryu.log"), "w")
    p = subprocess.Popen(["ryu-manager", "ryu.app.simple_switch_13", "ryu.app.ofctl_rest",
                          "--ofp-tcp-listen-port", str(OF_PORT)], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(0.5)
        if _controller_up():
            return p
    p.terminate()
    raise RuntimeError("Ryu no arrancó; revisa results/ryu.log")


def victim_iface(net):
    link = net.linksBetween(net.get("h1"), net.get("s1"))[0]
    return link.intf2.name


if __name__ == "__main__":      
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("info")
    ctrl = ensure_controller()
    n = build_net()
    start_net(n)
    CLI(n)
    n.stop()
    if ctrl:
        ctrl.terminate()
