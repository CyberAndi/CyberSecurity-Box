#!/bin/sh
clear
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
processes=$(uci commit && reload_config)
wait $processes  >> install.log
/etc/init.d/uhttpd restart  >> install.log

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
DEVICE_REVISION='v0.85'

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
echo

FILE=/www/luci-static/bootstrap/OCR-A.ttf
if [ ! -f "$FILE" ] 
	then
		if [ "$(ls /www/luci-static/bootstrap/c*.css)" != "" ]
			then
				processes=$(rm /www/luci-static/bootstrap/c*.css)
		fi

		wait $processes
		if [ "$(ls /www/luci-static/resources/view/dashboard/css/c*.css)" != "" ]
			then
				processes=$(rm /www/luci-static/resources/view/dashboard/css/c*.css)
		fi

		wait $processes
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/CyberSecurity-Box.png -P /www/luci-static/bootstrap/)
		wait $processes
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/CyberSecurity-Box.svg -P /www/luci-static/bootstrap/)
		wait $processes
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/CyberAndi.svg -P /www/luci-static/bootstrap/)
		wait $processes1
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/cascade.css -P /www/luci-static/bootstrap/)
		wait $processes1
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/OCR-A.ttf -P /www/luci-static/bootstrap/)
		wait $processes1
		processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/OCR-A.woff -P /www/luci-static/bootstrap/)
		wait $processes1

fi


FILE1=/www/luci-static/resources/view/dashboard/css/c*.css
if [ ! -f "$FILE" ]
	then
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/custom.css -P /www/luci-static/resources/view/dashboard/css/

		mv /www/luci-static/resources/view/status/include/*_system.js /www/luci-static/resources/view/status/include/90_system.js
		mv /www/luci-static/resources/view/status/include/*_memory.js /www/luci-static/resources/view/status/include/10_memory.js
		mv /www/luci-static/resources/view/status/include/*_storage.js /www/luci-static/resources/view/status/include/15_storage.js
		mv /www/luci-static/resources/view/status/include/*_dsl.js /www/luci-static/resources/view/status/include/20_dsl.js
		mv /www/luci-static/resources/view/status/include/*_ports.js /www/luci-static/resources/view/status/include/21_ports.js
		mv /www/luci-static/resources/view/status/include/*_network.js /www/luci-static/resources/view/status/include/22_network.js
		mv /www/luci-static/resources/view/status/include/*_dhcp.js /www/luci-static/resources/view/status/include/25_dhcp.js
		mv /www/luci-static/resources/view/status/include/*_wifi.js /www/luci-static/resources/view/status/include/30_wifi.js
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
 	uci delete wireless.radio0.disabled >> install.log
  	processes=$(uci commit && reload_config)
	wait $processes  >> install.log
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

wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/captiveportal.htm -O /www/CaptivePortal/index.htm)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/mobile.css -P /www/CaptivePortal/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/theme.css -P /www/CaptivePortal/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/theme_variable.css -P /www/CaptivePortal/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/prophetie.htm -P /www/CaptivePortal/)
#wait $processes1
#processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/OCR-A.ttf -P /www/CaptivePortal/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/OCRAStd.woff -P /www/CaptivePortal/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/Unwetter2.jpg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/Bibelserver.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/CMovie.svg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/virus.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/CMovie-Logo.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/CMovie-Play.svg -P /www/CaptivePortal/pic/)
#wait $processes1
#processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/Corona_2.svg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/csb.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/Münzen.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/search.svg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/search-128.svg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War.jpg -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_Foreground_Maske.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_Foreground_Maske_o.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_Maske.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeDust.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeDust2.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeFlammen.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeFlammen_o.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeHimmel.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/War_MaskeSchutt.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/WarMaske.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/WarMaskeSky.png -P /www/CaptivePortal/pic/)
wait $processes1
processes1=$(wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/pic_upload/WarMaskeSky_.png -P /www/CaptivePortal/pic/)

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
uci set uhttpd.main.listen_http='0.0.0.0:80' '[::]:80'
uci set uhttpd.main.listen_https='0.0.0.0:8443' '[::]:8443'
uci set uhttpd.main.index_page='index.php'
uci set uhttpd.main.interpreter='.php=/usr/bin/php-cgi'
processes=$(uci commit && reload_config)
wait $processes  >> install.log
}

#-------------------------start---------------------------------------

echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...' >> install.log
echo
echo >> install.log
echo $main_release
echo
echo 'Automation Install'
echo
echo >> install.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Customize Firmware' 
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Customize Firmware' >> install.log
customize_firmware >> install.log

echo
echo >> install.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot' >> install.log
create_hotspot >> install.log

echo
echo >> install.log
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S)' Create Hotspot' >> install.log
set_uhttpd >> install.log
