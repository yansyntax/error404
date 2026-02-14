#!/bin/bash
clear
XRAY_VERSION="24.10.31"
TMP_DIR="/tmp"
FILE="Xray-linux-64.zip"

echo "[INFO] Deteksi lokasi VPS..."
COUNTRY=$(curl -s https://ipinfo.io/country)
echo "[INFO] VPS terdeteksi di negara: $COUNTRY"

cd "$TMP_DIR" || exit 1
rm -f "$FILE"

if [[ "$COUNTRY" == "ID" ]]; then
    echo "[INFO] VPS Indonesia, download manual GitHub"

    curl -L -A "Mozilla/5.0" \
    -o "$FILE" \
    https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${FILE}

    unzip -o "$FILE"
    install -m 755 xray /usr/local/bin/xray

elif [[ "$COUNTRY" == "SG" ]]; then
    echo "[INFO] VPS Singapura, pakai installer resmi"

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
    @ install -u www-data --version ${XRAY_VERSION}

else
    echo "[INFO] Negara lain, download manual GitHub"

    curl -L -A "Mozilla/5.0" \
    -o "$FILE" \
    https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${FILE}

    unzip -o "$FILE"
    install -m 755 xray /usr/local/bin/xray
fi

echo "[INFO] Xray berhasil dipasang"
