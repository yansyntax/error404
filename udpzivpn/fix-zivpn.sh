#!/bin/bash

INSTALL_PATH="/usr/local/bin/install.sh"
UNINSTALL_PATH="/usr/local/bin/uninstall-zivpn"

# =====================================
# Fungsi download dengan deteksi negara
# =====================================
function download_script() {
    local url="$1"
    local output="$2"
    local country

    mkdir -p "$(dirname "$output")"  # pastikan folder ada

    # Deteksi negara pakai IP publik
    local ip
    ip=$(curl -s https://ipinfo.io/ip)
    country=$(curl -s https://ipinfo.io/"$ip"/country)
    echo "Detected country: $country"

    # Mirror khusus Indonesia
    if [[ "$country" == "ID" ]]; then
        url="${url/raw.githubusercontent.com/raw.fastgit.org}"
        echo "Using Indonesia mirror: $url"
    fi

    # Download file dengan curl (fallback wget)
    if command -v curl >/dev/null 2>&1; then
        curl -sSL "$url" -o "$output"
    else
        wget -q "$url" -O "$output"
    fi

    # Pastikan file bisa dieksekusi
    if [ -f "$output" ]; then
        chmod +x "$output"
        return 0
    else
        echo "Failed to download $output"
        return 1
    fi
}

# =====================================
# Backup ZiVPN lama
# =====================================
chattr -i /etc/zivpn/api_auth.key 2>/dev/null
echo "Backup ZiVPN..."
rm -rf /etc/zivpn-backup
cp -r /etc/zivpn /etc/zivpn-backup

# =====================================
# Uninstall ZiVPN lama
# =====================================
echo "Menghapus ZiVPN lama..."
if [ -f "$UNINSTALL_PATH" ]; then
    "$UNINSTALL_PATH"
else
    download_script "https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/uninstall.sh" "$UNINSTALL_PATH" \
        && "$UNINSTALL_PATH"
fi

# =====================================
# Install ZiVPN baru
# =====================================
echo "Install ZiVPN baru..."
apt update -y

if [ -f "$INSTALL_PATH" ]; then
    echo "Install script already exists, executing..."
    "$INSTALL_PATH"
else
    download_script "https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/install.sh" "$INSTALL_PATH" \
        && "$INSTALL_PATH"
fi

# =====================================
# Restore backup lama
# =====================================
echo "Restore ZiVPN backup..."
rm -rf /etc/zivpn
cp -r /etc/zivpn-backup /etc/zivpn

# =====================================
# Restart service
# =====================================
systemctl restart zivpn 2>/dev/null
systemctl restart zivpn-api 2>/dev/null

chattr +i /etc/zivpn/api_auth.key 2>/dev/null
echo "Update ZiVPN selesai!"
