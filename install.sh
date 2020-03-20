# !/bin/sh

set -e

#Datum erstellen
date=$(date --utc --date "$1" +%F)

HOMEDIR=$(pwd)

LOG=/var/log/CyberSecurity-Box_$date.log
echo $LOG

NEWLANG=de_DE.UTF-8
# Aenderungsdatum der LOG-Datei anpassen und Berechtigung Setzen
touch $LOG
chown pi:pi $LOG

#Fehler abfangen
trap 'error_report $LINENO' ERR

error_report() {

    echo "Installation in Zeile $1 fehlerhaft."

}

# Installation starten
echo "------ Linux aktualisieren ------" | tee -a $LOG

apt-get update | tee -a $LOG
apt-get upgrade -y | tee -a $LOG


clear
echo "----- Start der Installation ------" | tee -a $LOG
echo ""
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/privoxy/config > config | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/tor/torrc > torrc | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/regex.list > regex.list | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/whitelist_Alexa_Google_Home_Smarthome.txt > whitelist.txt | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/boxed-bg.jpg > boxed-bg.jpg | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/boxed-bg.png > boxed-bg.png | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/blockingpage.css > blockingpage.css | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/AdminLTE.min.css > AdminLTE.min.css | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/skin-blue.min.css > skin-blue.min.css | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/bootstrap.css > bootstrap.css | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/root.hints > root.hints | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf > unbound.conf | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf.d/test.conf > unbound_tor_pihole.conf | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf > root-auto-trust-anchor-file.conf | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/unbound/unbound.conf.d/qname-minimisation.conf > qname-minimisation.conf | tee -a $LOG
curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/Version2/ntopng.conf > ntopng.conf | tee -a $LOG

echo "-- IPTABLES installieren --" | tee -a $LOG
apt-get install ethtool iptables-persistent netfilter-persistent -y  | tee -a $LOG

echo "-- Tor und Privoxy installieren --" | tee -a $LOG
apt-get install tor privoxy -y  | tee -a $LOG

service privoxy stop
service tor stop
cp config /etc/privoxy/config | tee -a $LOG
cp torrc /etc/tor/torrc | tee -a $LOG

service tor start | tee -a $LOG
systemctl status tor | tee -a $LOG
service privoxy start | tee -a $LOG
systemctl status privoxy | tee -a $LOG


echo "-- Pi-Hole installieren --" | tee -a $LOG
curl -sSL https://install.pi-hole.net | bash  | tee -a $LOG
service pihole-FTL stop | tee -a $LOG

cp regex.list /etc/pihole/regex.list | tee -a $LOG
cp whitelist.txt /etc/pihole/whitelist.txt | tee -a $LOG
cp boxed-bg.jpg /var/www/html/admin/img/boxed-bg.jpg | tee -a $LOG
cp *.css /var/www/html/admin/style/vendor/ | tee -a $LOG
cp blockingpage.css /var/www/html/pihole/ | tee -a $LOG

service pihole-FTL start | tee -a $LOG
systemctl status pihole-FTL | tee -a $LOG


echo "-- UNBOUND local installieren --" | tee -a $LOG
mkdir /var/log/unbound | tee -a $LOG
echo > /var/log/unbound/unbound.log | tee -a $LOG

apt-get install unbound -y | tee -a $LOG
service unbound stop | tee -a $LOG

cp root.hints /var/lib/unbound/root.hints | tee -a $LOG
cp root.hints /etc/unbound/root.hints | tee -a $LOG
cp unbound.conf /etc/unbound/unbound.conf | tee -a $LOG
cp unbound_tor_pihole.conf /etc/unbound/unbound.conf.d/unbound_tor_pihole.conf | tee -a $LOG
cp root-auto-trust-anchor-file.conf /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf | tee -a $LOG
cp qname-minimisation.conf /etc/unbound/unbound.conf.d/qname-minimisation.conf | tee -a $LOG

service unbound start | tee -a $LOG
systemctl status unbound | tee -a $LOG

echo "-- NTOPNG local installieren --" | tee -a $LOG
apt-get install ntopng postfix -y | tee -a $LOG
cp bootstrap.css /var/lib/ntopng/ | tee -a $LOG
cp ntopng.conf /etc/ntopng.conf | tee -a $LOG
service ntopng restart | tee -a $LOG

echo "-- zwischengespeicherte Dateien loeschen --" | tee -a $LOG
rm *.* -rv | tee -a $LOG

echo "------ Installation der CyberSecurity-Box ist abgeschlossen ------" | tee -a $LOG
clear 
service --status-all  | tee -a $LOG


echo ""
echo "Drücken Sie eine beliebige Taste um die Firewall einzustellen ..."  | tee -a $LOG
stty -icanon -echo min 1 time 0
dd bs=1 count=1 >/dev/null 2>&1
clear

#Firewall Pihole Unbound Tor Transparentproxy

echo 0 > /proc/sys/net/ipv4/ip_forward
clear

#sichere alte Konfiguration
echo "Sichere alte Konfiguration" | tee -a $LOG
iptables-save > "/etc/iptables/rules.v4_old_"$date".bkp" | tee -a $LOG

#Locale Addresen
LOCALADDRESS="127.192.0.1/10"
echo "Inizialisiere Variablen für den Setup ...." | tee -a $LOG

#komplettes Internet
INTERNET="0.0.0.0/0"

#Internet Gateway
INET_GW="192.168.175.254"

#Zugriff auf Server
ACCESS_SERVER="192.168.175.200/24"

#Lokales LAN
LAN="192.168.0.0/16"

#Tor Netzwerk
TOR_ROUTING="10.192.0.0/10"

# alle Ziele welche nicht durch TOR geleitet werden
NON_TOR=$LAN 
echo "alle Ziele, welche nicht durch Tor gehen, wurden definiert"  | tee -a $LOG

# TV und VoD
BANKING_SRV="www.hvb.de www.hypovereinsbank.de my.hypovereinsbank.de"
JOYN_SRV="joyn.de joyn.tv"
ZATTOO_SRV="zattoo.de zattoo.ch zattoo.tv"
WAIPU_SRV="waipu.de waipu.com waipu.tv"
PRIME_SRV="s3-1-w.amazonaws.com"
NETFLIX_SRV="nflxvideo.net 54.204.25.0/28 23.23.189.144/28 34.195.253.0/25 35.163.200.168/28"
VIDEO_SRV="maxdome.com pluto.tv redbull.tv 52.192.0.0/11 99.86.3.59/24 18.236.7.30/11 217.148.99.11/28 46.137.171.215/11 34.241.244.104/24 207.45.72.215/11" 

#FORWARD_SRV= $VIDEO_SRV $NETFLIX_SRV $PRIME_SRV $WAIPU_SRV $ZATTOO_SRV $JOYN_SRV $BANKING_SRV 
echo "Variablen für Weiterleitungen wurden definiert" | tee -a $LOG

#SSL Ports
SSL_PORT="22"

#SMTP Port
SMTP_PORT="25"
SMTP_PORT2="465"
SMTP_PORT3="587"

#POP3 Port
POP3_PORT="110"
POP3_PORT2="995"

#IMAP4 Port
IMAP_PORT="143"
IMAP_PORT2="993"

#PiHole Port
PIHOLE_PORT="81"
PIHOLE_FTL_PORT="4711"

#DHCP Port
DHCP_PORT="67"

#Privoxy Port
PRIVOXY_PORT="8188"

#NTOPNG Port
NTOPNG_PORT="3000"

# http and https ports
HTTP_PORT="80"
HTTPS_PORT="443"

# DNS and SDNS ports
DNS_PORT="53"
SDNS_PORT="853"
DNS_TORRC="5053"
DNS_DNSCRYPT="5300"
DNS_UNBOUND="5353"

#Skype ports 
SKYPE_TCP_PORT="38562 1000:10000 50000:65000 16000:26000"
SKYPE_UDP_PORT="38562 3478:3481 50000:60000"

#Alexa ports
ALEXA_TCP_PORT="67:68 8080 40317 49317 33434 123 54838 55443 46053 1000:10000 50000:65000 16000:26000"
ALEXA_UDP_PORT="4070 5353 40317 49317 33434 50000:60000 3478:3481"

#NTP
NTP_PORT="123"

# the UID Tor runs as
TOR_UID="1000"

# Tor's TransPort
TRANS_PORT="9040"

# Tor's DirPort
DIR_PORT="9030"

# Tor's Relay NodePort
OR_PORT="9049"

# Tor's SocksPort
SOCKS_PORT="9050"

# Tor's ControlPort
CONTROL_PORT="9051"

# Tor'HTTPPort
THTTP_PORT="9060"

# Einstellungen löschen
echo "lösche alte Einstellungen" | tee -a $LOG
iptables -F | tee -a $LOG
iptables -t nat -F | tee -a $LOG
iptables -X | tee -a $LOG
iptables -t nat -X | tee -a $LOG

# Eigene CHAINS (IP-Table-Ablauf-Ketten)
iptables -N ACCEPT_L | tee -a $LOG
iptables -N DROP_L | tee -a $LOG
iptables -A ACCEPT_L -j LOG --log-prefix "FW ACCEPT - " | tee -a $LOG
iptables -A ACCEPT_L -j ACCEPT | tee -a $LOG
iptables -A DROP_L -j LOG --log-prefix "FW DROP - " | tee -a $LOG
iptables -A DROP_L -j DROP | tee -a $LOG

echo 1 > /proc/sys/net/ipv4/ip_forward | tee -a $LOG

#offene Verbindungen halten Satefull Inspection
iptables -I INPUT 1 -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I INPUT 1 -i lo -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I INPUT 1 -i eth0 -m state --state INVALID -j DROP_L | tee -a $LOG
iptables -I INPUT 1 -i lo -m state --state INVALID -j DROP_L | tee -a $LOG

iptables -I FORWARD 1 -i eth0 -o lo -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I FORWARD 1 -i eth0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I FORWARD 1 -i lo -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I FORWARD 1 -i lo -o lo -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I FORWARD 1 -i eth0 -o eth0 -m state --state INVALID -j DROP_L | tee -a $LOG
iptables -I FORWARD 1 -i lo -o lo -m state --state INVALID -j DROP_L | tee -a $LOG

iptables -I OUTPUT 1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 1 -o lo -m state --state ESTABLISHED,RELATED -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 1 -o eth0 -m state --state INVALID -j DROP_L | tee -a $LOG
iptables -I OUTPUT 1 -o lo -m state --state INVALID -j DROP_L | tee -a $LOG

#Ping Zugriff
iptables -I INPUT 2 -s $LAN -p ICMP -i eth0 -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 2 -p ICMP -d $INTERNET -o eth0 -j ACCEPT | tee -a $LOG
echo "Ping erlaubt" | tee -a $LOG

#ssh Zugriff
iptables -I INPUT 3 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $SSL_PORT -j ACCEPT  | tee -a $LOG
echo "SSH-Zugriff erlaubt" | tee -a $LOG

#Sperrt Zugriff
iptables -P INPUT DROP | tee -a $LOG

#Sperrt Weiterleitungen
iptables -P FORWARD DROP | tee -a $LOG

#Sperrt Abfragen
iptables -P OUTPUT DROP | tee -a $LOG

echo "Alles per DEFAULT gesperrt"
#iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN | tee -a $LOG


# DNS Zugriff
iptables -I INPUT 4 -i lo -p udp -s $LAN -d $ACCESS_SERVER --dport $DNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i lo -p udp -s $LAN -d $ACCESS_SERVER --dport $SDNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i lo -p tcp -s $LAN -d $ACCESS_SERVER --dport $DNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i lo -p tcp -s $LAN -d $ACCESS_SERVER --dport $SDNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i eth0 -p udp -s $LAN -d $ACCESS_SERVER --dport $DNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i eth0 -p udp -s $LAN -d $ACCESS_SERVER --dport $SDNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i eth0 -p tcp -s $LAN -d $ACCESS_SERVER --dport $DNS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 4 -i eth0 -p tcp -s $LAN -d $ACCESS_SERVER --dport $SDNS_PORT -j ACCEPT_L  | tee -a $LOG
echo "DNS Zugriff erlaubt" | tee -a $LOG

# Zugriff PiHole / httpdlight
iptables -I INPUT 5 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $PIHOLE_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 5 -p tcp -m tcp --dport $DHCP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 5 -p udp -m udp --dport $DHCP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 5 -p tcp -m tcp -i lo --dport $PIHOLE_FTL_PORT-j ACCEPT_L | tee -a $LOG
echo "PiHole Zugriff erlaubt" | tee -a $LOG

# Zugriff Web
iptables -I INPUT 6 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $HTTP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 6 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $HTTPS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 6 -p tcp -i lo -s $LAN -d $ACCESS_SERVER --dport $HTTP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 6 -p tcp -i lo -s $LAN -d $ACCESS_SERVER --dport $HTTPS_PORT -j ACCEPT_L | tee -a $LOG
echo "HTTP/s Zugriff erlaubt" | tee -a $LOG

# Zugriff Privoxy
iptables -I INPUT 7 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $PRIVOXY_PORT -j ACCEPT_L | tee -a $LOG
echo "Proxy Zugriff erlaubt" | tee -a $LOG

#Zugriff NTOPNG
iptables -I INPUT 8 -p tcp -i eth0 -s $LAN -d $ACCESS_SERVER --dport $NTOPNG_PORT -j ACCEPT_L | tee -a $LOG
echo "NTOPNG Zugriff erlaubt" | tee -a $LOG

#Zugriff TOR
iptables -I INPUT 9 -p tcp -d $ACCESS_SERVER --dport $DIR_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 9 -p tcp -d $ACCESS_SERVER --dport $TRANS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 9 -p tcp -d $ACCESS_SERVER --dport $OR_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 9 -p tcp -d $ACCESS_SERVER --dport $SOCKS_PORT -j ACCEPT_L | tee -a $LOG
iptables -I INPUT 9 -p tcp -d $ACCESS_SERVER --dport $THTTP_PORT -j ACCEPT_L | tee -a $LOG
echo "TOR Zugriff erlaubt" | tee -a $LOG


#Abfrage Web
iptables -I OUTPUT 10 -o eth0 -p tcp --dport $HTTP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 10 -o eth0 -p tcp --dport $HTTPS_PORT -j ACCEPT_L | tee -a $LOG
echo "Web-Abfrage erlaubt"

#Abfrage DNS
iptables -I OUTPUT 11 -p udp --dport $DNS_PORT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $SDNS_PORT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_PORT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $SDNS_PORT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_TORRC -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $DNS_DNSCRYPT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $DNS_UNBOUND -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_DNSCRYPT -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_UNBOUND -o lo -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $DNS_PORT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $SDNS_PORT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_PORT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $SDNS_PORT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_TORRC -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $DNS_DNSCRYPT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p udp --dport $DNS_UNBOUND -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_DNSCRYPT -o eth0 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 11 -p tcp --dport $DNS_UNBOUND -o eth0 -j ACCEPT_L | tee -a $LOG
echo "DNS-Abfragen erlaubt" | tee -a $LOG


#Abfrage NTP
iptables -I OUTPUT 12 -p tcp --dport $NTP_PORT -o eth0 -j ACCEPT_L | tee -a $LOG
echo "NTP-Abfrage erlaubt" | tee -a $LOG

#Abfrage TOR
iptables -I OUTPUT 13 -p tcp --dport $DIR_PORT -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 13 -p tcp --dport $TRANS_PORT -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 13 -p tcp --dport $OR_PORT -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 13 -p tcp --dport $SOCKS_PORT -j ACCEPT | tee -a $LOG
iptables -I OUTPUT 13 -p tcp --dport $THTTP_PORT -j ACCEPT | tee -a $LOG
echo "TOR-Abfragen erlaubt" | tee -a $LOG

#Abfrage SMTP
iptables -I OUTPUT 14 -p tcp --dport $SMTP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 14 -p tcp --dport $SMTP_PORT2 -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 14 -p tcp --dport $SMTP_PORT3 -j ACCEPT_L | tee -a $LOG
echo "SMTP-Abfrage erlaubt" | tee -a $LOG

#Abfrage IMAP
iptables -I OUTPUT 15 -p tcp --dport $IMAP_PORT -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 15 -p tcp --dport $IMAP_PORT2 -j ACCEPT_L | tee -a $LOG
echo "IMAP-Abfrage erlaubt" | tee -a $LOG

#Abfrage POP3
iptables -I OUTPUT 16 -p tcp --dport $POP3_PORT -j ACCEPT_L | tee -a $LOG
iptables -I OUTPUT 16 -p tcp --dport $POP3_PORT2 -j ACCEPT_L | tee -a $LOG
echo "POP3-Abfrage erlaubt" | tee -a $LOG

#Routingpakete makieren
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE | tee -a $LOG

for NET in $NON_TOR 127.0.0.0/9 127.128.0.0/10; do
 iptables -t nat -A OUTPUT -d $NET -j RETURN | tee -a $LOG
done

# Weiterleitung für Video, TV usw.

for NET1 in $VIDEO_SRV $NETFLIX_SRV $PRIME_SRV $WAIPU_SRV $ZATTOO_SRV $JOYN_SRV $BANKING_SRV; do
	iptables -A FORWARD -d $NET1 -i eth0 -o eth0 -m state --state NEW -j ACCEPT | tee -a $LOG
	iptables -t nat -A PREROUTING -p tcp -d $NET1 --dport $HTTPS_PORT -j REDIRECT --to-ports $HTTPS_PORT | tee -a $LOG
	iptables -t nat -A OUTPUT -p tcp -d $NET1 --dport $HTTPS_PORT -o lo -j REDIRECT --to-ports $HTTPS_PORT | tee -a $LOG
	iptables -t nat -A PREROUTING -p tcp -d $NET1 --dport $HTTP_PORT -j REDIRECT --to-ports $HTTP_PORT | tee -a $LOG
	iptables -t nat -A OUTPUT -p tcp -d $NET1 --dport $HTTP_PORT -o lo -j REDIRECT --to-ports $HTTP_PORT | tee -a $LOG
done
echo "Weiterleitungen aktiviert" | tee -a $LOG

#iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
#iptables -A FORWARD -m string --string "s3-1-w.amazonaws.com" --algo kmp -d $INET_GW -j ACCEPT | tee -a $LOG
#iptables -A FORWARD -m string --string ".ix.nflxvideo.net" --algo kmp -d $INET_GW -j ACCEPT | tee -a $LOG
#iptables -A FORWARD -m string --string ".joyn.de" --algo kmp -d $INET_GW -j ACCEPT | tee -a $LOG
#iptables -A FORWARD -m string --string ".joyn.net" --algo kmp -d $INET_GW -j ACCEPT | tee -a $LOG

# NAT für TOR und DNS over Tor

iptables -t nat -A PREROUTING 20 -p tcp -d $LOCALADDRESS --dport $SSL_PORT -j REDIRECT --to-ports $SSL_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -d $LOCALADDRESS --dport $SSL_PORT -j REDIRECT --to-ports $SSL_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $SSL_PORT -j REDIRECT --to-ports $SSL_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $SSL_PORT -j REDIRECT --to-ports $SSL_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $DNS_PORT -j REDIRECT --to-ports $DNS_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $DNS_PORT -j REDIRECT --to-ports $DNS_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $SDNS_PORT -j REDIRECT --to-ports $SDNS_PORT | tee -a $LOG 
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $SDNS_PORT -j REDIRECT --to-ports $SDNS_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp -d $LOCALADDRESS --dport $PIHOLE_PORT -j REDIRECT --to-ports $PIHOLE_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -d $LOCALADDRESS --dport $PIHOLE_PORT -j REDIRECT --to-ports $PIHOLE_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $PIHOLE_PORT -j REDIRECT --to-ports $PIHOLE_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $PIHOLE_PORT -j REDIRECT --to-ports $PIHOLE_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp -d $LOCALADDRESS --dport $NTOPNG_PORT -j REDIRECT --to-ports $NTOPNG_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -d $LOCALADDRESS --dport $NTOPNG_PORT -j REDIRECT --to-ports $NTOPNG_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $NTOPNG_PORT -j REDIRECT --to-ports $NTOPNG_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $NTOPNG_PORT -j REDIRECT --to-ports $NTOPNG_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp -d $TOR_ROUTING --dport $HTTPS_PORT -j REDIRECT --to-ports $SOCKS_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -d $TOR_ROUTING --dport $HTTPS_PORT -j REDIRECT --to-ports $SOCKS_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $HTTP_PORT -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $HTTP_PORT -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --dport $HTTPS_PORT -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --dport $HTTPS_PORT -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG
iptables -t nat -A PREROUTING 20 -p tcp --syn -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG
iptables -t nat -A OUTPUT 20 -p tcp -o lo --syn -j REDIRECT --to-ports $TRANS_PORT | tee -a $LOG

echo "Tor-TransparentProxy aktiviert" | tee -a $LOG

for NET in $NON_TOR 127.0.0.0/8; do
 iptables -A OUTPUT 21 -d $NET -j ACCEPT | tee -a $LOG
done
iptables -A OUTPUT 21 -m owner --uid-owner $TOR_UID -j ACCEPT | tee -a $LOG
iptables -A OUTPUT 21 -j REJECT | tee -a $LOG
echo "" | tee -a $LOG
echo "" | tee -a $LOG
echo "Firewall eingerichtet"  | tee -a $LOG
echo "" | tee -a $LOG
echo "Firewall-Status Abfrage" | tee -a $LOG
echo "" | tee -a $LOG

iptables-save > /etc/iptables/rules.v4 | tee -a $LOG
#clear

iptables -L -v | grep -v "0     0" | tee -a $LOG
iptables -L -v -t nat | grep -v "0     0" | tee -a $LOG
echo ""
echo "Für den Neustart"
echo "Drücken Sie eine beliebige Taste ..." 
stty -icanon -echo min 1 time 0
dd bs=1 count=1 >/dev/null 2>&1
echo ""
reboot

