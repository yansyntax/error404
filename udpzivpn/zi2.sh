# Decrypted by LT | FUSCATOR
# Github- https://github.com/LunaticTunnel/Absurd

set -euo pipefail
YELLOW='\033[1;33m'
RED='\033[0;31m'
LIGHT_BLUE='\033[1;36m'  # biru muda terang
BOLD_WHITE='\033[1;37m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
LIGHT_GREEN='\033[1;32m'
NC='\033[0m' # No Color
LICENSE_URL="https://raw.githubusercontent.com/yansyntax/permission/main/regist"
LICENSE_INFO_FILE="/etc/zivpn/.license_info"
function verify_license() {
echo "Verifying installation license..."
local SERVER_IP
SERVER_IP=$(cat /etc/zivpn/ip.txt)
if [ -z "$SERVER_IP" ]; then
echo -e "${RED}Failed to retrieve server IP. Please check your internet connection.${NC}"
exit 1
fi
local license_data
license_data=$(curl -s "$LICENSE_URL")
if [ $? -ne 0 ] || [ -z "$license_data" ]; then
echo -e "${RED}Gagal terhubung ke server lisensi. Mohon periksa koneksi internet Anda.${NC}"
exit 1
fi
local license_entry
license_entry=$(echo "$license_data" | grep -w "$SERVER_IP")
if [ -z "$license_entry" ]; then
echo -e "${RED}Verifikasi Lisensi Gagal! IP Anda tidak terdaftar. IP: ${SERVER_IP}${NC}"
exit 1
fi
local client_name
local expiry_date_str
client_name=$(echo "$license_entry" | awk '{print $1}')
expiry_date_str=$(echo "$license_entry" | awk '{print $2}')
local expiry_timestamp
expiry_timestamp=$(date -d "$expiry_date_str" +%s)
local current_timestamp
current_timestamp=$(date +%s)
if [ "$expiry_timestamp" -le "$current_timestamp" ]; then
echo -e "${RED}Verifikasi Lisensi Gagal! Lisensi untuk IP ${SERVER_IP} telah kedaluwarsa. Tanggal Kedaluwarsa: ${expiry_date_str}${NC}"
exit 1
fi
echo -e "${LIGHT_GREEN}Verifikasi Lisensi Berhasil! Client: ${client_name}, IP: ${SERVER_IP}${NC}"
sleep 2 # Brief pause to show the message
mkdir -p /etc/zivpn
echo "CLIENT_NAME=${client_name}" > "$LICENSE_INFO_FILE"
echo "EXPIRY_DATE=${expiry_date_str}" >> "$LICENSE_INFO_FILE"
}
verify_license
BIN_URL="https://github.com/arivpnstores/udp-zivpn/releases/download/zahidbd2/udp-zivpn-linux-arm64"
CFG_URL="https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/config.json"
BIN_PATH="/usr/local/bin/zivpn"
CFG_DIR="/etc/zivpn"
CFG_PATH="${CFG_DIR}/config.json"
KEY_PATH="${CFG_DIR}/zivpn.key"
CRT_PATH="${CFG_DIR}/zivpn.crt"
UDP_LISTEN_PORT="5667"
DNAT_FROM_MIN="6000"
DNAT_FROM_MAX="19999"
echo "[1/9] Updating server"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
echo "[2/9] Stop service if exists"
systemctl stop zivpn.service 2>/dev/null || true
echo "[3/9] Downloading UDP Service (arm64) + config"
mkdir -p "${CFG_DIR}"
wget -qO "${BIN_PATH}" "${BIN_URL}"
chmod +x "${BIN_PATH}"
wget -qO "${CFG_PATH}" "${CFG_URL}"
echo "[4/9] Generating cert files (if missing)"
if [[ ! -f "${KEY_PATH}" || ! -f "${CRT_PATH}" ]]; then
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
-keyout "${KEY_PATH}" -out "${CRT_PATH}"
fi
echo "[5/9] Persist sysctl (survive reboot)"
cat >/etc/sysctl.d/99-zivpn-udp.conf <<EOF
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF
sysctl --system >/dev/null
echo "[6/9] Force password config to [\"zi\"]"
sed -i -E 's/"config"[[:space:]]*:[[:space:]]*\[[^]]*\]/"config": ["zi"]/g' "${CFG_PATH}"
echo "Config berhasil diupdate menjadi: [\"zi\"]"
echo "[7/9] Create systemd service (wait network online)"
cat >/etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=zivpn VPN Server
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
WorkingDirectory=${CFG_DIR}
ExecStartPre=/bin/sh -c 'test -s "${CFG_PATH}" && test -s "${KEY_PATH}" && test -s "${CRT_PATH}"'
ExecStart=${BIN_PATH} server -c ${CFG_PATH}
Restart=on-failure
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable zivpn.service >/dev/null
echo "[8/9] Persist NAT rule across reboot (iptables-persistent)"
apt-get install -y iptables-persistent >/dev/null
DEF_IF="$(ip -4 route ls | awk '/default/ {print $5; exit}')"
if [[ -z "${DEF_IF}" ]]; then
echo "❌ Gagal mendeteksi interface default. Cek: ip -4 route"
exit 1
fi
if ! iptables -t nat -C PREROUTING -i "${DEF_IF}" -p udp --dport "${DNAT_FROM_MIN}:${DNAT_FROM_MAX}" -j DNAT --to-destination ":${UDP_LISTEN_PORT}" 2>/dev/null; then
iptables -t nat -A PREROUTING -i "${DEF_IF}" -p udp --dport "${DNAT_FROM_MIN}:${DNAT_FROM_MAX}" -j DNAT --to-destination ":${UDP_LISTEN_PORT}"
fi
iptables-save > /etc/iptables/rules.v4
echo "[9/9] UFW rules (optional) + start service"
if command -v ufw >/dev/null 2>&1; then
ufw allow "${DNAT_FROM_MIN}:${DNAT_FROM_MAX}/udp" >/dev/null || true
ufw allow "${UDP_LISTEN_PORT}/udp" >/dev/null || true
fi
systemctl restart zivpn.service
echo ""
echo "✅ ZIVPN UDP Installed (arm64) & reboot-safe"
echo "- Interface: ${DEF_IF}"
echo "- DNAT UDP ${DNAT_FROM_MIN}-${DNAT_FROM_MAX} -> :${UDP_LISTEN_PORT}"
echo "- Check: systemctl status zivpn --no-pager"
