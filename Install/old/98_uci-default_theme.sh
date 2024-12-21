release=$(cat /etc/openwrt_release | grep "DISTRIB_RELEASE" | cut -f2 -d '=')
revision=$(cat /etc/openwrt_release | grep "DISTRIB_REVISION" | cut -f2 -d '=')
revision=${revision::-1}
release=${release::-1}
revision=${revision:1}
release=${release:1}
main_release=$(cat /etc/openwrt_release | grep "DISTRIB_RELEASE" | cut -f2 -d '=' | cut -f1 -d '.' | cut -c 2-)
architecture=$(cat /etc/openwrt_release | grep "ARCH" | cut -f2 -d '=')
target=$(cat /etc/openwrt_release | grep "TARGET" | cut -f2 -d '=')
architecture=${architecture::-1}
target=${target::-1}
architecture=${architecture:1}
target=${target:1}
LOCALADDRESS="127.192.0.1/10"
actLoop=$(ifconfig | grep '^l\w*' -m 1 | cut -f1 -d ' ')
actEth=$(ifconfig | grep '^e\w*' -m 1 | cut -f1 -d ' ')
actWlan=$(ifconfig | grep '^w\w*' -m 1 | cut -f1 -d ' ')
INET_GW=$(ip route | grep default | cut -f3  -d ' ')
INET_GW_org=$INET_GW
WAN_ip=$(echo $INET_GW | cut -f1 -d '.')
WAN_ip=$WAN_ip'.'$(echo $INET_GW | cut -f2 -d '.')
WAN_ip=$WAN_ip'.'$(echo $INET_GW | cut -f3 -d '.')'.250'
WAN_broadcast=$(echo $INET_GW | cut -f1 -d '.')
WAN_broadcast=$WAN_broadcast'.'$(echo $INET_GW | cut -f2 -d '.')
WAN_broadcast=$WAN_broadcast'.'$(echo $INET_GW | cut -f3 -d '.')'.255'
WAN_MOBILE_ip=$(echo $INET_GW | cut -f1 -d '.')
WAN_MOBILE_ip=$WAN_ip'.'$(echo $INET_GW | cut -f2 -d '.')
WAN_MOBILE_ip=$WAN_ip'.'$(echo $INET_GW | cut -f3 -d '.')'.251'
WAN_MOBILE_broadcast=$(echo $INET_GW | cut -f1 -d '.')
WAN_MOBILE_broadcast=$WAN_broadcast'.'$(echo $INET_GW | cut -f2 -d '.')
WAN_MOBILE_broadcast=$WAN_broadcast'.'$(echo $INET_GW | cut -f3 -d '.')'.255'
WAN_MOBILE_GW=$(echo $INET_GW | cut -f1 -d '.')
WAN_MOBILE_GW=$WAN_ip'.'$(echo $INET_GW | cut -f2 -d '.')
WAN_MOBILE_GW=$WAN_ip'.'$(echo $INET_GW | cut -f3 -d '.')'.253'
Internet="0.0.0.0/0"
all_IP="0.0.0.0"
all_IP6="[::]"
ACCESS_SERVER=$(echo $($(echo ip addr show dev $(echo $actEth | cut -f1 -d' ')) | grep inet | cut -f6 -d ' ' ) | cut -f1 -d ' ' )
IPv6=""
IPv6=$(echo $(echo $($(echo ip addr show dev $(echo $actEth | cut -f1 -d' ')) | grep inet | cut -f6 -d ' ' ) | cut -f1 -d ' ' ) | cut -c 5-6)
if [ "$IPv6" = "::" ]
	then
		LAN=''
fi
if [ "$LAN" = "" ]
        then
                LAN='192.168.1.1'
fi
LAN_org=$LAN
if [ "$LAN" = "" ]
        then
                LAN=$LAN_org
fi
LOCAL_DOMAIN='CyberSecBox.local'
WIFI_SSID='CyberSecBox'
WIFI_PASS='Cyber,Sec9ox'
SUBNET=$(echo $LAN | cut -f3 -d '.')
SUBNET_sep=$SUBNET
if [ $SUBNET_sep -lt 125 ]
        then
                if  [ $SUBNET_sep -lt 5 ]
                        then
                                SUBNET_sep=$(($SUBNET_sep + 6))
                fi
		SUBNET_sep=$(($SUBNET_sep + 125))
        else
                if  [ $SUBNET_sep -gt 250 ]
                        then
                                SUBNET_sep=$(($SUBNET_sep - 62))
                fi
fi
TOR_ONION='1'
SDNS_PORT='y'
DNSMASQ_Relay_port='5353'
STUBBY='1'
DNS_STUBBY_port='5453'
DNS_IP='127.0.0.1'
DNS_PORT='y'
UNBOUND='1'
UNBOUND_Relay_port='9053'
VLAN_ENABLE='1'
FW_HSactive='1'
SERVER_range='192.168.'$(($SUBNET_sep - 123))'.10,192.168.'$(($SUBNET_sep - 123))'.200,24h'
CONTROL_range='192.168.'$(($SUBNET_sep - 119))'.10,192.168.'$(($SUBNET_sep - 119))'.200,24h'
HCONTROL_range='192.168.'$(($SUBNET_sep - 118))'.10,192.168.'$(($SUBNET_sep - 118))'.200,24h'
INET_range='192.168.'$SUBNET_sep'.2,192.168.'$SUBNET_sep'.200,24h'
VOICE_range='192.168.'$(($SUBNET_sep + 1))'.10,192.168.'$(($SUBNET_sep + 1))'.200,24h'
ENTERTAIN_range='192.168.'$(($SUBNET_sep - 1))'.10,192.168.'$(($SUBNET_sep - 1))'.200,24h'
GUEST_range='192.168.'$(($SUBNET_sep + 10))'.10,192.168.'$(($SUBNET_sep + 10))'.200,24h'
CMOVIE_range='192.168.'$(($SUBNET_sep + 9))'.10,192.168.'$(($SUBNET_sep + 9))'.200,24h'
TELEKOM_range='192.168.'$(($SUBNET_sep + 8))'.10,192.168.'$(($SUBNET_sep + 8))'.200,24h'
LAN_range='192.168.1.10,192.168.1.200,24h'
SERVER_ip='192.168.'$(($SUBNET_sep - 123))'.254'
CONTROL_ip='192.168.'$(($SUBNET_sep - 119))'.254'
HCONTROL_ip='192.168.'$(($SUBNET_sep - 118))'.254'
INET_ip='192.168.'$SUBNET_sep'.1'
VOICE_ip='192.168.'$(($SUBNET_sep + 1))'.1'
ENTERTAIN_ip='192.168.'$(($SUBNET_sep - 1))'.1'
GUEST_ip='192.168.'$(($SUBNET_sep + 10))'.1'
CMOVIE_ip='192.168.'$(($SUBNET_sep + 9))'.1'
TELEKOM_ip='192.168.'$(($SUBNET_sep + 8))'.1'
LAN_ip='192.168.1.1'
SERVER_broadcast='192.168.'$(($SUBNET_sep - 123))'.255'
CONTROL_broadcast='192.168.'$(($SUBNET_sep - 119))'.255'
HCONTROL_broadcast='192.168.'$(($SUBNET_sep - 118))'.255'
INET_broadcast='192.168.'$SUBNET_sep'.255'
VOICE_broadcast='192.168.'$(($SUBNET_sep + 1))'.255'
ENTERTAIN_broadcast='192.168.'$(($SUBNET_sep - 1))'.255'
GUEST_broadcast='192.168.'$(($SUBNET_sep + 10))'.255'
CMOVIE_broadcast='192.168.'$(($SUBNET_sep + 9))'.255'
TELEKOM_broadcast='192.168.'$(($SUBNET_sep + 8))'.255'
LAN_broadcast='192.168.1.255'
SERVER_lan='192.168.'$(($SUBNET_sep - 123))'.0'
CONTROL_lan='192.168.'$(($SUBNET_sep - 119))'.0'
HCONTROL_lan='192.168.'$(($SUBNET_sep - 118))'.0'
INET_lan='192.168.'$SUBNET_sep'.0'
VOICE_lan='192.168.'$(($SUBNET_sep + 1))'.0'
ENTERTAIN_lan='192.168.'$(($SUBNET_sep - 1))'.0'
GUEST_lan='192.168.'$(($SUBNET_sep + 10))'.0'
CMOVIE_lan='192.168.'$(($SUBNET_sep + 9))'.0'
TELEKOM_lan='192.168.'$(($SUBNET_sep + 8))'.0'
LAN_lan='192.168.1.9'
SERVER_net=$SERVER_ip'/24'
CONTROL_net=$CONTROL_ip'/24'
HCONTROL_net=$HCONTROL_ip'/24'
INET_net=$INET_ip'/24'
VOICE_net=$VOICE_ip'/24'
ENTERTAIN_net=$ENTERTAIN_ip'/24'
GUEST_net=$GUEST_ip'/24'
CMOVIE_net=$CMOVIE_ip'/24'
WAN_net=$WAN_ip'/24'
WAN_MOBILE_net=$WAN_MOBILE_ip'/24'
LAN_net='192.168.1.1/24'
SERVER_domain='server.'$LOCAL_DOMAIN
CONTROL_domain='control.'$LOCAL_DOMAIN
HCONTROL_domain='hcontrol.'$LOCAL_DOMAIN
INET_domain='inet.'$LOCAL_DOMAIN
VOICE_domain='voice.local'
ENTERTAIN_domain='entertain.local'
GUEST_domain='guest.local'
CMOVIE_domain='cmovie.local'
LAN_domain='local'
ONION_domain='onion'
EXIT_domain='exit'
SERVER_ssid='DMZ-'$WIFI_SSID
CONTROL_ssid='Control-'$WIFI_SSID
HCONTROL_ssid='HControl-'$WIFI_SSID
INET_ssid='iNet-'$WIFI_SSID
VOICE_ssid='Voice-'$WIFI_SSID
ENTERTAIN_ssid='Entertain-'$WIFI_SSID
GUEST_ssid='Guest-'$WIFI_SSID
CMOVIE_ssid='Free_CMovie_Portal'
Adversisment_ssid='Telekom'
TELEKOM_ssid='Telekom'
LAN_ssid=$WIFI_SSID
uci del dhcp.lan.ra_slaac >/dev/null
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='1'
uci add_list network.@bridge-vlan[-1].ports='lan1'
uci add_list network.@bridge-vlan[-1].ports='lan2'
uci add_list network.@bridge-vlan[-1].ports='lan3'
uci add_list network.@bridge-vlan[-1].ports='lan4'
uci set network.lan.device='br-lan.1'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='1'
uci set network.@bridge-vlan[-1].vid='1'
uci add_list network.@bridge-vlan[-1].ports='lan1:u*'
uci add_list network.@bridge-vlan[-1].ports='lan2:u*'
uci add_list network.@bridge-vlan[-1].ports='lan3:u*'
uci add_list network.@bridge-vlan[-1].ports='lan4:u*'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='101'
uci set network.@bridge-vlan[-1].vid='101'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='102'
uci set network.@bridge-vlan[-1].vid='102'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='103'
uci set network.@bridge-vlan[-1].vid='103'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='104'
uci set network.@bridge-vlan[-1].vid='104'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='105'
uci set network.@bridge-vlan[-1].vid='105'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='106'
uci set network.@bridge-vlan[-1].vid='106'
uci add_list network.@bridge-vlan[-1].ports='lan1:t' 
uci add_list network.@bridge-vlan[-1].ports='lan2:t' 
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='107'
uci set network.@bridge-vlan[-1].vid='107'
uci add_list network.@bridge-vlan[-1].ports='lan1:t'
uci add_list network.@bridge-vlan[-1].ports='lan2:t'
uci add_list network.@bridge-vlan[-1].ports='lan3:t' 
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='108'
uci set network.@bridge-vlan[-1].vid='108'
uci add_list network.@bridge-vlan[-1].ports='lan1:t'
uci add_list network.@bridge-vlan[-1].ports='lan2:t'
uci add_list network.@bridge-vlan[-1].ports='lan3:t'
uci add_list network.@bridge-vlan[-1].ports='lan4:t'
uci add network bridge-vlan
processes=$(uci commit && reload_config)
wait $processes
uci add network interface >> install.log
uci rename network.@interface[-1]='GUEST'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$GUEST_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$GUEST_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.107'
uci add network interface >> install.log
uci rename network.@interface[-1]='ENTERTAIN'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$ENTERTAIN_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$ENTERTAIN_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.106'
uci add network interface >> install.log
uci rename network.@interface[-1]='VOICE'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$VOICE_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$VOICE_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.105'
uci add network interface >> install.log
uci rename network.@interface[-1]='INET'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$INET_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$INET_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.104'
uci add network interface >> install.log
uci rename network.@interface[-1]='CONTROL'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$CONTROL_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$CONTROL_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.103'
uci add network interface >> install.log
uci rename network.@interface[-1]='HCONTROL'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$HCONTROL_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$HCONTROL_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.102'
uci add network interface >> install.log
uci rename network.@interface[-1]='SERVER'
uci set network.@interface[-1].proto='static'
uci set network.@interface[-1].ipaddr=$SERVER_ip
uci set network.@interface[-1].netmask='255.255.255.0'
uci set network.@interface[-1].ip6assign='56'
uci set network.@interface[-1].broadcast=$SERVER_broadcast
uci set network.@interface[-1].gateway=$INET_GW
uci set network.@interface[-1].dns=$INET_GW
uci set network.@interface[-1].device='br-lan.101'
uci set dhcp.CONTROL=dhcp
uci set dhcp.CONTROL.interface='CONTROL'
uci set dhcp.CONTROL.start='1'
uci set dhcp.CONTROL.limit='250'
uci set dhcp.CONTROL.leasetime='24h'
uci set dhcp.CONTROL.dhcpv4='server'
uci set dhcp.HCONTROL=dhcp
uci set dhcp.HCONTROL.interface='HCONTROL'
uci set dhcp.HCONTROL.start='1'
uci set dhcp.HCONTROL.limit='250'
uci set dhcp.HCONTROL.leasetime='24h'
uci set dhcp.HCONTROL.dhcpv4='server'
uci set dhcp.INET=dhcp
uci set dhcp.INET.interface='INET'
uci set dhcp.INET.start='1'
uci set dhcp.INET.limit='250'
uci set dhcp.INET.leasetime='24h'
uci set dhcp.INET.dhcpv4='server'
uci set dhcp.SERVER=dhcp
uci set dhcp.SERVER.interface='SERVER'
uci set dhcp.SERVER.start='1'
uci set dhcp.SERVER.limit='250'
uci set dhcp.SERVER.leasetime='24h'
uci set dhcp.SERVER.dhcpv4='server'
uci set dhcp.VOICE=dhcp
uci set dhcp.VOICE.interface='VOICE'
uci set dhcp.VOICE.start='1'
uci set dhcp.VOICE.limit='250'
uci set dhcp.VOICE.leasetime='24h'
uci set dhcp.VOICE.dhcpv4='server'
uci set dhcp.ENTERTAIN=dhcp
uci set dhcp.ENTERTAIN.interface='ENTERTAIN'
uci set dhcp.ENTERTAIN.start='1'
uci set dhcp.ENTERTAIN.limit='250'
uci set dhcp.ENTERTAIN.leasetime='24h'
uci set dhcp.ENTERTAIN.dhcpv4='server'
uci set dhcp.GUEST=dhcp
uci set dhcp.GUEST.interface='GUEST'
uci set dhcp.GUEST.start='1'
uci set dhcp.GUEST.limit='250'
uci set dhcp.GUEST.leasetime='24h'
uci set dhcp.GUEST.dhcpv4='server'
uci add_list firewall.@zone[0].network='lan'
uci add_list firewall.@zone[0].network='INET'
uci add_list firewall.@zone[0].network='CONTROL'
uci add_list firewall.@zone[0].network='HCONTROL'
uci add_list firewall.@zone[0].network='SERVER'
uci add_list firewall.@zone[0].network='VOICE'
uci add_list firewall.@zone[0].network='ENTERTAIN'
uci add_list firewall.@zone[0].network='GUEST'
uci commit && reload_config
uci set system.@system[0]=system
uci set system.@system[0].ttylogin='0'
uci set system.@system[0].log_size='64'
uci set system.@system[0].urandom_seed='0'
uci set system.@system[0].log_proto='udp'
uci set system.@system[0].conloglevel='1'
uci set system.@system[0].cronloglevel='9'
uci set system.@system[0].timezone='CET-1CEST,M3.5.0,M10.5.0/3'
uci set system.@system[0].zonename='Europe/Berlin'
uci set system.@system[0].hostname='CyberSecurity-Box'
uci set system.@system[0].description='CyberSecurity-Box with Tor-Onion-Services'
uci delete system.ntp.server
uci add_list system.ntp.server=$INET_GW 
uci add_list system.ntp.server='0.openwrt.pool.ntp.org'
uci add_list system.ntp.server='1.pool.ntp.org'
uci add_list system.ntp.server='2.openwrt.pool.ntp.org'
uci add_list system.ntp.server='3.pool.ntp.org'
uci set uhttpd.defaults.country='DE'
uci set uhttpd.defaults.state=''
uci set uhttpd.defaults.location='DMZ'
uci set uhttpd.defaults.commonname=$LAN
uci -q delete uhttpd.main.listen_http
uci add_list uhttpd.main.listen_http="0.0.0.0:80"
uci add_list uhttpd.main.listen_http="[::]:80"
uci -q delete uhttpd.main.listen_https
uci add_list uhttpd.main.listen_https="0.0.0.0:8443"
uci add_list uhttpd.main.listen_https="[::]:8443"
uci set luci.main.mediaurlbase='/luci-static/bootstrap-dark'
uci set uhttpd.main.redirect_https='1'
uci commit && reload_config
/etc/init.d/uhttpd restart
uci set wireless.default_radio1.ssid='CyberSec-Box'
uci set wireless.default_radio0.ssid='CyberSec-Box'
uci set wireless.default_radio1.encryption='sae'
uci set wireless.default_radio1.key=$WIFI_PASS
uci set wireless.default_radio0.encryption='sae'
uci set wireless.default_radio0.key=$WIFI_PASS
uci set wireless.radio0.channel='auto'
uci set wireless.radio1.channel='auto'
uci delete wireless.radio0.disabled
uci delete wireless.radio1.disabled
processes=$(uci commit && reload_config)
uci set unbound.ub_main.listen_port='5353'
uci commit && reload_config
/etc/init.d/unbound restart
cat << EOF > /etc/banner
  +++         +                  +++               +++++
 +   +        +                 +   +              +    +
+             +                 +                  +    + 
+             +                 +                  +    +
+      +   +  +++    ++   +  ++  +++    ++    ++   +++++    ++   +   +
+       + +   +  +  +  +  + +       +  +  +  +  +  +    +  +  +   + +
+        +    +  +  +++   ++        +  +++   +     +    +  +  +    +
 +   +   +    +  +  +     +     +   +  +     +  +  +    +  +  +   + +
  +++    +    +++    +++  +      +++    +++   ++   +++++    ++   +   +
 
      local Privacy for Voice-Assistents, Smart-TVs and SmartHome 
	   
--------------------------------------------------------------------------
   powered by OpenWrt $(echo $release), $(echo $revision)
--------------------------------------------------------------------------
EOF
cat << EOF > /etc/openwrt_release
DISTRIB_ID='CyberSecurity-Box'
DISTRIB_RELEASE='$(echo $release)'
DISTRIB_REVISION='$(echo $revision)'
DISTRIB_TARGET='$(echo $target)'
DISTRIB_ARCH='$(echo $architecture)'
DISTRIB_DESCRIPTION='CyberSecurity-Box $(echo $revision)'
DISTRIB_TAINTS=''
EOF
cat << EOF > /etc/device_info
DEVICE_MANUFACTURER='@CyberAndi'
DEVICE_MANUFACTURER_URL='https://cyberandi.tumblr.com/'
DEVICE_PRODUCT='CyberSecurity-Box'
DEVICE_REVISION='v0.78'
EOF
cat << EOF > /etc/rc.local
FILE=/www/luci-static/bootstrap/OCR-A.ttf
if [ ! -f "$FILE" ] 
	then
		if [ "$(ls /www/luci-static/bootstrap/c*.css)" != "" ]
			then
				rm /www/luci-static/bootstrap/c*.css
				rm /www/luci-static/resources/view/dashboard/css/c*.css
		fi
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/CyberSecurity-Box.png -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/CyberSecurity-Box.svg -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/CyberAndi.svg -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/cascade.css -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/OCR-A.ttf -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/OCR-A.woff -P /www/luci-static/bootstrap/
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/openWRT23_install.sh -P /root/
fi
FILE1=/www/luci-static/resources/view/dashboard/css/c*.css
if [ ! -f "$FILE" ]
	then
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberAndi-Pi-Hole-5/custom.css -P /www/luci-static/resources/view/dashboard/css/
fi
/root/*.sh
exit 0
EOF
