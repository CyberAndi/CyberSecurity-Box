#!/bin/sh
clear
mv /www/index.html /www/index.old
release=$(grep "DISTRIB_RELEASE" /etc/openwrt_release | cut -f2 -d '=')
revision=$(grep "DISTRIB_REVISION" /etc/openwrt_release | cut -f2 -d '=')
revision=${revision::-1}
release=${release::-1}
revision=${revision:1}
release=${release:1}
main_release=$(grep "DISTRIB_RELEASE" /etc/openwrt_release | cut -f2 -d '=' | cut -f1 -d '.' | cut -c 2-)
architecture=$(grep "ARCH" /etc/openwrt_release | cut -f2 -d '=')
target=$(grep "TARGET" /etc/openwrt_release | cut -f2 -d '=')
architecture=${architecture::-1}
target=${target::-1}
architecture=${architecture:1}
target=${target:1}

LOCALADDRESS="127.192.0.1/10"

actLoop=$(ifconfig | grep '^l\w*' -m 1 | cut -f1 -d ' ')
actEth=$(ifconfig | grep '^e\w*' -m 1 | cut -f1 -d ' ')
actWlan=$(ifconfig | grep '^w\w*' -m 1 | cut -f1 -d ' ')

#Internet Gateway
if [ ! -z "$1" ]  
	then
		INET_GW=$1
	else
		INET_GW=$(ip route | grep default | cut -f3  -d ' ')
fi
INET_GW_org=$INET_GW
echo
#read -p 'Please give me the WAN-IP (Gateway/Router): ['$INET_GW'] ' INET_GW
echo
if [ "$INET_GW" = "" ]
	then
		INET_GW=$INET_GW_org
fi

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

#complet Internet
Internet="0.0.0.0/0"

#all Adresses
all_IP="0.0.0.0"
all_IP6="[::]"

#Access to Server
ACCESS_SERVER=$(echo $($(echo ip addr show dev $(echo $actEth | cut -f1 -d' ')) | grep inet | cut -f6 -d ' ' ) | cut -f1 -d ' ' )

#Lokal LAN
if [ ! -z "$2" ]
	then
		LAN=$2
	else
		LAN=$(echo $($(echo ip addr show dev $(echo $actEth | cut -f1 -d' ')) | grep 'inet ' | cut -f6 -d ' ' ) | cut -f1 -d ' ' | cut -f1 -d'/' )
fi

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

#read -p 'Type the LAN-IP (Internal Network): ['$( echo $LAN )'] ' LAN
if [ "$LAN" = "" ]
        then
                LAN=$LAN_org
fi

check_hash() {
    local file=$1
    echo "$EXPECTED_HASH  $file" | sha256sum -c
}

check_download()  {
	local URL=$1
	local EXPECTED_HASH=$2
	local OUTPUT_FILE=$3
	echo >> /root/install_customice.log
	echo $URL >> /root/install_customice.log
	echo $EXPECTED_HASH >> /root/install_customice.log
	echo $OUTPUT_FILE >> /root/install_customice.log


	wget --waitretry=10 -t 5 -O "/root/$OUTPUT_FILE" "$URL"
    
	if [[ $? -eq 0 ]]; then
    	if check_hash "$OUTPUT_FILE"; then
        	echo "Hash is okay"  >> /root/install_customice.log
        	break
    	else
       		echo "$OUTPUT_FILE" | sha256sum >> /root/install_customice.log
        	rm -f "$OUTPUT_FILE" && echo 'del file false Hash' >> /root/install_customice.log
    	fi
	fi    
}

customize_firmware() {
	FILE=/www/luci-static/resources/view/dashboard/css/c*.css
	if [ ! -f "$FILE" ]
		then
			customize_firmware_sub
	fi
}

customize_firmware_sub() {
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
uci set uhttpd.main.index_page='index.php'
uci set uhttpd.main.interpreter='.php=/usr/bin/php-cgi'
uci set luci.main.mediaurlbase='/luci-static/bootstrap-dark'
uci set uhttpd.main.redirect_https='1'
uci set luci.diag.ping='cmovie.4lima.de'
uci set luci.diag.route='brave.com'
uci set luci.diag.dns='bible4u2lvhacg4b3to2e2veqpwmrc2c3tjf2wuuqiz332vlwmr4xbad.onion'
uci set network.wan6.disabled='1'
uci set wireless.default_radio0.ssid='CyberSec-Box'
uci set wireless.default_radio1.ssid='CyberSec-Box'
uci set uhttpd.main.index_page='index.php'
uci set uhttpd.main.interpreter='.php=/usr/bin/php-cgi'
processes=$(uci commit && reload_config)
wait $processes  >> /root/install_customice.log
/etc/init.d/uhttpd restart  >> /root/install_customice.log
/etc/init.d/network restart  >> /root/install_customice.log
echo
echo 'Default Country-Settings'
echo 

echo
echo 'https activated'
echo

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
DEVICE_REVISION='v0.95'
EOF

cat << EOF > /etc/sysupgrade.conf
## This file contains files and directories that should
## be preserved during an upgrade.

/etc/openWRT_install.sh
/etc/banner
/etc/device_info
/etc/openwrt_release
/etc/config/
/www/
EOF

datum=$(date +"%y%d%m%H%M")
echo $datum
sleep 30
FILE=/www/luci-static/bootstrap/OCR-A.ttf
echo $datum >> /root/install_customice.log
if [ ! -f "$FILE" ] 
	then
		echo 'file not found - download' >> /root/install_customice.log
		if [ "$(ls /www/luci-static/bootstrap/c*.css)" != "" ]
			then
				processes52=$(rm /www/luci-static/bootstrap/c*.css)
    			wait $processes52 && echo 'delete c*.css' >> /root/install_customice.log
		fi

		if [ "$(ls /www/luci-static/resources/view/dashboard/css/c*.css)" != "" ]
			then
				processes51=$(rm /www/luci-static/resources/view/dashboard/css/c*.css)
    			wait $processes51 && echo 'delete dashboard c*.css' >> /root/install_customice.log
		fi
		#process50=$(wget --waitretry=10 -t 5 -O /root/openWRT23_install.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh)
    	#wait $process50 && echo 'download retry openWRT23_install.sh' >> /root/install_customice.log

		if [ "$(ls /www/luci-static/bootstrap/logo.svg)" != "" ]
			then
				processe53s=$(rm /www/luci-static/bootstrap/logo*.* >> /root/install_customice.log)
    			wait $processes53 && echo 'delete logo.svg' >> /root/install_customice.log
		fi

		process=$(check_download "https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh" "b86e524d522def9ee4f032667f2bff088e3a185a1e8cfe3f7e663fae98af8022" "openWRT23_install.sh")
		wait $process && echo 'download openWRT23_install.sh' >> /root/install_customice.log
		process1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/logo.svg -P /www/)
    	wait $process1 && echo 'download logo.svg' >> /root/install_customice.log
	  	process2=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/index.php -P /www/)
    	wait $process2	&& echo 'download index.php' >> /root/install_customice.log
 		process3=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/output.php -P /www/)
		wait $process3 && echo 'download output.php' >> /root/install_customice.log
		process4=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/CyberSecurity-Box.png -P /www/luci-static/bootstrap/)
		wait $process4 && echo 'download CyberSecurity-Box.png' >> /root/install_customice.log
		process5=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/CyberSecurity-Box.svg -P /www/luci-static/bootstrap/)
		wait $process5 && echo 'download CyberSecurity-Box.svg' >> /root/install_customice.log
		process6=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/CyberAndi.svg -P /www/luci-static/bootstrap/)
		wait $process6 && echo 'download CyberAndi.svg' >> /root/install_customice.log
		process7=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/cascade.css -P /www/luci-static/bootstrap/)
		wait $process7 && echo 'download cascade.css' >> /root/install_customice.log
		process8=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/OCR-A.ttf -P /www/luci-static/bootstrap/)
		wait $process8 && echo 'download OCR-A.ttf' >> /root/install_customice.log
		process9=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/OCR-A.woff -P /www/luci-static/bootstrap/)
		wait $process9 && echo 'download OCR-A.woff' >> /root/install_customice.log
		process10=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/logo.svg -P /www/luci-static/bootstrap/)
		wait $process10 && echo 'download logo.svg' >> /root/install_customice.log
		process11=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/bootstrap/logo_48.png -P /www/luci-static/bootstrap/)
		wait $process11 && echo 'download logo_48.png' >> /root/install_customice.log
fi

FILE1=/www/luci-static/resources/view/dashboard/css/c*.css
if [ ! -f "$FILE" ]
	then
		mv /www/luci-static/resources/view/status/include/*_dsl.js /www/luci-static/resources/view/status/include/10_dsl.js
		mv /www/luci-static/resources/view/status/include/*_ports.js /www/luci-static/resources/view/status/include/11_ports.js
		mv /www/luci-static/resources/view/status/include/*_mwan3.js /www/luci-static/resources/view/status/include/14_mwan3.js
		mv /www/luci-static/resources/view/status/include/*_network.js /www/luci-static/resources/view/status/include/15_network.js
		mv /www/luci-static/resources/view/status/include/*_dhcp.js /www/luci-static/resources/view/status/include/30_dhcp.js
		mv /www/luci-static/resources/view/status/include/*_wifi.js /www/luci-static/resources/view/status/include/20_wifi.js
		mv /www/luci-static/resources/view/status/include/*_memory.js /www/luci-static/resources/view/status/include/80_memory.js
		mv /www/luci-static/resources/view/status/include/*_storage.js /www/luci-static/resources/view/status/include/85_storage.js
		mv /www/luci-static/resources/view/status/include/*_system.js /www/luci-static/resources/view/status/include/90_system.js
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/luci-static/resources/view/dashboard/custom.css -P /www/luci-static/resources/view/dashboard/css/
fi

echo
echo 'On Error enter logread'
echo
}

create_hotspot(){
	FILE=/www/CaptivePortal/pic
	uci set wireless.radio0=wifi-device
	uci set wireless.radio0.type='mac80211'
	uci set wireless.radio0.path='platform/soc/a000000.wifi'
	uci set wireless.radio0.htmode='HT20'
	uci set wireless.radio0.country='DE'
	uci set wireless.radio0.channel='auto'
	uci set wireless.radio0.hwmode='11n'
	uci delete wireless.radio0.disabled >> /root/install_customice.log
	processes=$(uci commit && reload_config)
	wait $processes  >> /root/install_customice.log
	if [ ! -d "$FILE" ]
		then
			create_hotspot_sub
	fi
}

create_hotspot_sub() {
	FILE=/www/CaptivePortal/pic
	mkdir -p /www/router
	mkdir -p /www/redirect
	mkdir -p /www/CaptivePortal
	mkdir -p /www/generate_204	
	mkdir -p /www/CaptivePortal/pic
	processe=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/index.htm -P /www/)
	wait $processe && echo 'download index.htm' >> /root/install_customice.log
	processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/captiveportal.htm -O /www/CaptivePortal/index.htm)
	wait $processes1 && echo 'download captiveportal.htm' >> /root/install_customice.log
	processes2=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/mobile.css -P /www/CaptivePortal/)
	wait $processes2 && echo 'download mobile.css' >> /root/install_customice.log
	processes3=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/theme.css -P /www/CaptivePortal/)
	wait $processes3 && echo 'download theme.css' >> /root/install_customice.log
	processes4=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/theme_variable.css -P /www/CaptivePortal/)
	wait $processes4 && echo 'download theme_variable.css' >> /root/install_customice.log
	processes5=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/prophetie.htm -P /www/CaptivePortal/)
	wait $processes5 && echo 'download prophetie.htm' >> /root/install_customice.log
	processes6=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/OCR-A.ttf -P /www/CaptivePortal/)
	wait $processes6 && echo 'download OCR-A.ttf' >> /root/install_customice.log
	processes7=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/OCRAStd.woff -P /www/CaptivePortal/)
	wait $processes7 && echo 'download OCRAStd.woff' >> /root/install_customice.log
	processes8=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/Unwetter2.jpg -P /www/CaptivePortal/pic/)
	wait $processes8 && echo 'download Unwetter2.jpg' >> /root/install_customice.log
	processes9=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/Bibelserver.png -P /www/CaptivePortal/pic/)
	wait $processes9 && echo 'download Bibelserver.png' >> /root/install_customice.log
	processes10=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/CMovie.svg -P /www/CaptivePortal/pic/)
	wait $processes10 && echo 'download CMovie.svg' >> /root/install_customice.log
	processes11=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/virus.png -P /www/CaptivePortal/pic/)
	wait $processes11 && echo 'download virus.png' >> /root/install_customice.log
	processes12=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/CMovie-Logo.png -P /www/CaptivePortal/pic/)
	wait $processes12 && echo 'download CMovie-Logo.png' >> /root/install_customice.log
	processes13=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/CMovie-Play.svg -P /www/CaptivePortal/pic/)
	wait $processes13 && echo 'download CMovie-Play.svg' >> /root/install_customice.log
	#processes14=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/Corona_2.svg -P /www/CaptivePortal/pic/)
	#wait $processes14 && echo 'download Corona_2.svg' >> /root/install_customice.log
	processes15=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/csb.png -P /www/CaptivePortal/pic/)
	wait $processes15 && echo 'download csb.png' >> /root/install_customice.log
	processes16=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/Münzen.png -P /www/CaptivePortal/pic/)
	wait $processes16 && echo 'download Münzen.png' >> /root/install_customice.log
	processes17=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/search.svg -P /www/CaptivePortal/pic/)
	wait $processes17 && echo 'download search.svg' >> /root/install_customice.log
	processes18=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/search-128.svg -P /www/CaptivePortal/pic/)
	wait $processes18 && echo 'download search-128.svg' >> /root/install_customice.log
	processes19=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War.jpg -P /www/CaptivePortal/pic/)
	wait $processes19 && echo 'download War.jpg' >> /root/install_customice.log
	processes20=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_Foreground_Maske.png -P /www/CaptivePortal/pic/)
	wait $processes20 && echo 'download War_Foreground_Maske.png' >> /root/install_customice.log
	processes21=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_Foreground_Maske_o.png -P /www/CaptivePortal/pic/)
	wait $processes21 && echo 'download War_Foreground_Maske_o.png' >> /root/install_customice.log
	processes22=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_Maske.png -P /www/CaptivePortal/pic/)
	wait $processes22 && echo 'download War_Maske.png' >> /root/install_customice.log
	processes23=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeDust.png -P /www/CaptivePortal/pic/)
	wait $processes23 && echo 'download War_MaskeDust.png' >> /root/install_customice.log
	processes24=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeDust2.png -P /www/CaptivePortal/pic/)
	wait $processes24 && echo 'download War_MaskeDust2.png' >> /root/install_customice.log
	processes25=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeFlammen.png -P /www/CaptivePortal/pic/)
	wait $processes25 && echo 'download War_MaskeFlammen.png' >> /root/install_customice.log
	processes26=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeFlammen_o.png -P /www/CaptivePortal/pic/)
	wait $processes26 && echo 'download War_MaskeFlammen_o.png' >> /root/install_customice.log
	processes27=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeHimmel.png -P /www/CaptivePortal/pic/)
	wait $processes27 && echo 'download War_MaskeHimmel.png' >> /root/install_customice.log
	processes28=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/War_MaskeSchutt.png -P /www/CaptivePortal/pic/)
	wait $processes28 && echo 'download War_MaskeSchutt.png' >> /root/install_customice.log
	processes29=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/WarMaske.png -P /www/CaptivePortal/pic/)
	wait $processes29 && echo 'download WarMaske.png' >> /root/install_customice.log
	processes30=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/WarMaskeSky.png -P /www/CaptivePortal/pic/)
	wait $processes30 && echo 'download WarMaskeSky.png' >> /root/install_customice.log
	processes31=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/CaptivePortal/pic/WarMaskeSky_.png -P /www/CaptivePortal/pic/)
	wait $processes31 && echo 'download WarMaskeSky_.png' >> /root/install_customice.log
	echo
	echo 'On Error enter logread'
	echo
}

set_uhttpd() {
	uci set uhttpd.main=uhttpd
	uci set uhttpd.main.redirect_https='1'
	uci set uhttpd.main.home='/www'
	uci set uhttpd.main.rfc1918_filter='1'
	uci set uhttpd.main.max_requests='3'
	uci set uhttpd.main.max_connections='100'
	uci set uhttpd.main.cert='/etc/uhttpd.crt'
	uci set uhttpd.main.key='/etc/uhttpd.key'
	uci set uhttpd.main.cgi_prefix='/cgi-bin'
	uci set uhttpd.main.lua_prefix='/cgi-bin/luci=/usr/lib/lua/luci/sgi/uhttpd.lua'
	uci set uhttpd.main.script_timeout='60'
	uci set uhttpd.main.network_timeout='30'
	uci set uhttpd.main.http_keepalive='20'
	uci set uhttpd.main.tcp_keepalive='1'
	uci set uhttpd.main.ubus_prefix='/ubus'
	uci set uhttpd.main.index_page='index.php'
	uci set uhttpd.main.interpreter='.php=/usr/bin/php-cgi'
	processes=$(uci commit && reload_config)
	wait $processes  >> /root/install_customice.log
}

#-------------------------start---------------------------------------

echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...' >> /root/install_customice.log
echo
echo >> /root/install_customice.log
echo $main_release
echo
echo 'Automation Install'
echo
echo >> /root/install_customice.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Customize Firmware' 
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Customize Firmware' >> /root/install_customice.log
customize_firmware >> /root/install_customice.log

echo
echo >> /root/install_customice.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot' >> /root/install_customice.log
create_hotspot >> /root/install_customice.log

echo
echo >> /root/install_customice.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Set uhttpd'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Set uhttpd' >> /root/install_customice.log
set_uhttpd >> /root/install_customice.log

cat << EOF > /etc/rc.local
	if [ ! -f /root/openWRT23_install.sh ] && [ ! -f www/luci-static/bootstrap/cascade.css ]
		then
			rm /www/index.html && sleep 20 >> /root/install_rc_local.log
			if [ ! -f /root/customize_firmware.sh ] 
			then
				wget --waitretry=10 -t 5 -O /root/customize_firmware.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/customize_firmware.sh && sh /root/customize_firmware.sh  >> /root/install_rc_local.log & wait
			fi
			wget --waitretry=10 -t 5 -O /root/openWRT23_install.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh >> /root/install_rc_local.log
			wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/index.php -P /www/ >> /root/install_rc_local.log
			wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/output.php -P /www/ >> /root/install_rc_local.log
		else
			rm /root/*.sh >> /root/install_rc_local.log
			rm /root/*.sh.* >> /root/install_rc_local.log
	fi
	if [ ! -f /root/run ] 
		then
			echo ' $(date) ' > /root/run >> /root/install_rc_local.log
			rm /root/customize_firmware.sh >> /root/install_rc_local.log
			exit 0
	fi
	echo '$(date) ' >> /root/install_rc_local.log
	cat /etc/rc.local >> /root/install_rc_local.log
	rm /etc/rc.local >> /root/install_rc_local.log
	echo "" > /www/phpinfo.php
	echo "exit 0" > /etc/rc.local
EOF