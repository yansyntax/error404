# Decrypted by LT | FUSCATOR
# Github- https://github.com/LunaticTunnel/Absurd

set -e
echo "🔄 Updating ZiVPN Manager..."
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/install.sh \
-O /usr/local/bin/install.sh
chmod +x /usr/local/bin/install.sh
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/zivpn-manager \
-O /usr/local/bin/zivpn-manager
chmod +x /usr/local/bin/zivpn-manager
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/zivpn_helper.sh \
-O /usr/local/bin/zivpn_helper.sh
chmod +x /usr/local/bin/zivpn_helper.sh
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/update.sh \
-O /usr/local/bin/update-manager
chmod +x /usr/local/bin/update-manager
echo "🎉 ZiVPN Update completed successfully."
/usr/local/bin/zivpn-manager
