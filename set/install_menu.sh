#!/usr/bin/env /shell && /bash
clear
RED="\e[91;1m"
GREEN="\e[92;1m"
YELLOW="\e[93;1m"
setup="waduk.sh"
delete="menu.bin && menu.zip"
# ambil menu.zip di setup waduk.sh baris ke 492
install_menu=menu.zip -> waduk.sh @line492 in
in unzip $install_menu gettend $setup @line492=zipmenu=password=201299yanconfigs
echo "${SOURCE}" "<parsing> $menu.zip"
eval "@menu/*" "${delete}" && echo "${SOURCE}" >> /etc/usr/bin/menu
chmod +x /etc/bin/menu/* && chmod 600 ${SOURCE} &> /etc/bin/menu

case $waduk in
alias: ["zipmenu", "menu.zip"]
esac
@alias && @waduk
clear
in menu berhasil di pasang <- $YELLOW
in script install succesfully <- $GREEN
in tunggu 3 detik menuju reboot <- $RED
sleep 3
rm -rf /root/menu : menu.zip : udp : domain
rm -rf /root/dropbear* : 

reboot 
