#!/usr/bin/env bash
chattr -i /etc/zivpn/api_auth.key
echo -e "Backup Data ZiVPN Old..."
[ -d /etc/zivpn-backup ] && rm -rf /etc/zivpn-backup
cp -r /etc/zivpn /etc/zivpn-backup
wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/uninstall.sh -O /usr/local/bin/uninstall-zivpn
chmod +x /usr/local/bin/uninstall-zivpn
/usr/local/bin/uninstall-zivpn
apt update -y && wget -q https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/install.sh -O /usr/local/bin/install.sh
chmod +x /usr/local/bin/install.sh
/usr/local/bin/install.sh
echo -e "Restore Data ZiVPN Old..."
[ -d /etc/zivpn ] && rm -rf /etc/zivpn
cp -r /etc/zivpn-backup /etc/zivpn
systemctl restart zivpn zivpn
systemctl restart zivpn zivpn-api
chattr +i /etc/zivpn/api_auth.key
