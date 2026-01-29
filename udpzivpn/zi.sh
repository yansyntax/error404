#!/bin/bash

echo "Updating server"
apt-get update -y && apt-get upgrade -y

# Stop service if exists
systemctl stop zivpn.service 2>/dev/null

echo "Downloading ZIVPN binary"
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
chmod +x /usr/local/bin/zivpn

# Prepare directory
mkdir -p /etc/zivpn

# Download config
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/config.json -O /etc/zivpn/config.json

echo "Generating certificate"
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
-subj "/C=US/ST=CA/L=LA/O=ZIVPN/OU=IT/CN=zivpn" \
-keyout /etc/zivpn/zivpn.key \
-out /etc/zivpn/zivpn.crt

# === NETWORK BUFFER (RAM 1 GB FRIENDLY) ===
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.wmem_max=4194304

# Persist sysctl
grep -q rmem_max /etc/sysctl.conf || echo "net.core.rmem_max=4194304" >> /etc/sysctl.conf
grep -q wmem_max /etc/sysctl.conf || echo "net.core.wmem_max=4194304" >> /etc/sysctl.conf

# === SYSTEMD SERVICE (DIBATASI RAM) ===
cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json

# STABILITY
Restart=always
RestartSec=5

# MEMORY SAFETY (PENTING UNTUK RAM 1 GB)
MemoryHigh=250M
MemoryMax=300M
TasksMax=100

Environment=ZIVPN_LOG_LEVEL=info

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable zivpn
systemctl start zivpn

# === FIREWALL ===
IFACE=$(ip -4 route | grep default | awk '{print $5}' | head -n1)

iptables -t nat -C PREROUTING -i $IFACE -p udp --dport 6000:19999 -j DNAT --to :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 6000:19999 -j DNAT --to :5667

ufw allow 6000:19999/udp
ufw allow 5667/udp

echo "ZIVPN UDP Installed & Tuned"
