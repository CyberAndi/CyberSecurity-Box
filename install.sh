# !/bash

# Installation starten
clear
echo ----- Start der Installation ---

apt-get install tor unbound privoxy ntopng postfix iptables-persistent netfilter-persistent -y
curl -sSL https://install.pi-hole.net | bash

service pihole-FTL stop
service unbound stop
service privoxy stop
service tor stop
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/regex.list > regex.list
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/whitelist_Alexa_Google_Home_Smarthome.txt > whitelist.txt
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/tor/torrc > torrc
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/unbound/root.hints > root.hints
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/unbound/unbound.conf > unbound.conf
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/tree/Version2/unbound/unbound.conf.d > unbound.conf.d
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/privoxy/config > config
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/boxed-bg.jpg > boxed-bg.jpg
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/boxed-bg.png > boxed-bg.png
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/blockingpage.css > blockingpage.css
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/AdminLTE.min.css > AdminLTE.min.css
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/blob/Version2/skin-blue.min.css > skin-blue.min.css

cp regex.list /etc/pihole/regex.list
cp whitelist.txt /etc/pihole/whitelist.txt
cp root.hints /etc/unbound/root.hints
cp unbound.conf /etc/unbound/unbound.conf
cp unbound.conf.d /etc/unbound/unbound.conf.d -r -v
cp config /etc/privoxy/config
cp boxed-bg.jpg /var/www/html/admin/img/boxed-bg.jpg
cp *.css /var/www/html/admin/style/vendor/
cp blockingpage.css /var/www/html/pihole/

service tor start
service privoxy start
service unbound start
service pihole-FTL start

echo ----- Installation der CyberSecurity-Box ist abgeschlossen ---