#!/usr/bin/env bash
# Instalación de dependencias (probado en la lógica para Ubuntu 20.04 / 22.04).
# Ejecutar con un usuario con sudo. Los scripts del proyecto se ejecutan luego con sudo
# (Mininet necesita root), por eso los paquetes de Python se instalan a nivel de sistema.
set -e
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch hping3 tshark iperf3 curl python3-pip
sudo pip3 install -r requirements.txt
# Ryu necesita esta versión de eventlet para funcionar
sudo pip3 install ryu "eventlet==0.30.2"
echo "Listo. Verifica con: which ryu-manager hping3 tshark iperf3 mn"
