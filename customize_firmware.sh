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
uci set uhttpd.main.index_page='index.html'
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
DEVICE_REVISION='v0.78'

EOF

FILE=/root/openWRT*.sh
if [ "$(ls openWRT*.sh)" != "" ]
	then
		cp openWRT*.sh /etc/openWRT_install.sh
fi

chmod 0755 /etc/openWRT_install.sh

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

#Datum erstellen
#actdate(date --utc --date "$1" +%F)
datum=$(date +"%y%d%m%H%M")
echo

#sichere alte Konfiguration
echo 'Sichere alte Konfiguration'
#iptables-save > rules.v4_old_$datum.bkp

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

customize_firmware
