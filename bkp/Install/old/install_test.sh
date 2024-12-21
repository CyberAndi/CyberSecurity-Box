#!/bin/sh
clear

sudo su
apt-get update
apt-get upgrade -y

apt-get install tor unbound privoxy ntopng postfix iptables-persistent netfilter-persistent -y
curl -sSL https://install.pi-hole.net | bash

service pihole-FTL stop
service unbound stop
service privoxy stop
service tor stop
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/whitelist_Alexa_Google_Home_Smarthome.txt > whitelist.txt
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/tor/torrc > torrc
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/root.hints > root.hints
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf > unbound.conf
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf.d/test.conf > unbound_tor_pihole.conf
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound.sh > unbound.sh
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/privoxy/config > config
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/boxed-bg.jpg > boxed-bg.jpg
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/boxed-bg.png > boxed-bg.png
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/blockingpage.css > blockingpage.css
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/AdminLTE.min.css > AdminLTE.min.css
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/skin-blue.min.css > skin-blue.min.css

cp whitelist.txt /etc/pihole/whitelist.txt
cp root.hints /etc/unbound/root.hints
cp unbound.conf /etc/unbound/unbound.conf
cp unbound.sh /etc/cron.weekly
cp unbound_tor_pihole.conf /etc/unbound/unbound.conf.d/unbound_tor_pihole.conf -r -v
cp config /etc/privoxy/config
cp boxed-bg.jpg /var/www/html/admin/img/boxed-bg.jpg
cp *.css /var/www/html/admin/style/vendor/
cp blockingpage.css /var/www/html/pihole/

service tor start
service privoxy start
service unbound start
service pihole-FTL start
