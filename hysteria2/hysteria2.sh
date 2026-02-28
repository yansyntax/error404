#!/bin/bash
export LANG=en_US.UTF-8

### ===== FIXED AUTO CONFIG =====
AUTO_SNI="www.cloudflare.com"
AUTO_FIRSTPORT=10000
AUTO_ENDPORT=65535
AUTO_PORT=$(shuf -i 2000-65535 -n 1)
AUTO_PROXYSITE="speedtest.net"
AUTO_AUTH_PWD=$(date +%s%N | md5sum | cut -c 1-16)
### =============================

DEFAULT_SNI="www.bing.com"
MASQUERADE_URL="speedtest.net"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

[[ $EUID -ne 0 ]] && red "Run as root" && exit 1

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

installHysteria(){

    realip

    apt-get update
    apt -y install curl wget sudo qrencode procps iptables-persistent netfilter-persistent openssl

    wget -N https://raw.githubusercontent.com/yansyntax/error404/main/hysteria2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    [[ ! -f /usr/local/bin/hysteria ]] && red "Install failed" && exit 1

    ### ===== CERT (SELF SIGNED, AUTO) =====
    sni_host="$AUTO_SNI"
    hy_host="$AUTO_SNI"
    cert_path="/etc/hysteria/cert.crt"
    key_path="/etc/hysteria/private.key"

    mkdir -p /etc/hysteria
    openssl ecparam -genkey -name prime256v1 -out $key_path
    openssl req -new -x509 -days 36500 -key $key_path -out $cert_path -subj "/CN=$sni_host"
    chmod 777 $cert_path $key_path

    ### ===== PORT & PORT HOP =====
    port="$AUTO_PORT"
    firstport="$AUTO_FIRSTPORT"
    endport="$AUTO_ENDPORT"

    iptables -t nat -F PREROUTING
    ip6tables -t nat -F PREROUTING

    iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
    ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port

    netfilter-persistent save >/dev/null 2>&1

    ### ===== AUTH & OBFS (DEFAULT) =====
    auth_pwd="$AUTO_AUTH_PWD"
    obfs_server_config_key="obfs"

    ### ===== SERVER CONFIG =====
    cat > /etc/hysteria/config.yaml <<EOF
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

obfs:
  type: salamander
  salamander:
    password: $auth_pwd

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$AUTO_PROXYSITE
    rewriteHost: true
EOF

    ### ===== CLIENT CONFIG =====
    last_port="$port,$firstport-$endport"
    mkdir -p /root/hy

    cat > /root/hy/hy-client.yaml <<EOF
server: $ip:$last_port
auth: $auth_pwd
tls:
  sni: $hy_host
  insecure: true
obfs: $auth_pwd
EOF

    cat > /root/hy/hy-client.json <<EOF
{
  "server": "$ip:$last_port",
  "auth": "$auth_pwd",
  "tls": { "sni": "$hy_host", "insecure": true },
  "obfs": "$auth_pwd"
}
EOF

    url="hy2://$auth_pwd@$ip:$last_port/?insecure=1&sni=$hy_host&obfs=salamander&obfs-password=$auth_pwd#HttpInjector-hysteria2"
    echo "$url" > /root/hy/url.txt

    ### ===== SYSTEMD SERVICE =====
    cat > /lib/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl restart hysteria-server

    green "DONE"
    green "URI:"
    cat /root/hy/url.txt
}

installHysteria