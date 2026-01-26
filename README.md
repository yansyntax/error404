
# UP REPO DEBIAN
<pre><code>apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot</code></pre>
# UP REPO UBUNTU
<pre><code>apt update && apt upgrade -y && update-grub && sleep 2 && reboot</pre></code>

### INSTALL SCRIPT 
<pre><code>wget -q https://raw.githubusercontent.com/yansyntax/error404/main/waduk.sh && chmod +x waduk.sh && ./waduk.sh
</code></pre>

### UDP ZIVPN
UDP server installation for ZIVPN Tunnel (SSH/DNS/UDP) VPN app.
<br>

>Server binary for Linux amd64 and arm.

#### Installation AMD
```
wget -O zi.sh https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/zi.sh; sudo chmod +x zi.sh; sudo ./zi.sh
```

#### Installation ARM
```
bash <(curl -fsSL https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/zi2.sh)
```


### Uninstall

```
sudo wget -O ziun.sh https://raw.githubusercontent.com/yansyntax/error404/main/udpzivpn/uninstall.sh; sudo chmod +x ziun.sh; sudo ./ziun.sh
```

Client App available:

<a href="https://play.google.com/store/apps/details?id=com.zi.zivpn" target="_blank" rel="noreferrer">Download APP on Playstore</a>
> ZIVPN
                
----
Bash script by PowerMX

### TESTED ON OS 
- UBUNTU 20,22,24,25
- DEBIAN 10,11,12,13
