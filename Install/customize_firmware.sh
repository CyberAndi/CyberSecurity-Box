#!/bin/sh
clear
/etc/init.d/uhttpd stop >> /root/install_customice.log
mv /www/index.html /www/index.old

rm *.tar.gz 
rm *.log
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


echo '--------------------------------------------------------'
echo '       Current Version ' $release','  $revision
echo '--------------------------------------------------------'
echo 'Target '$target
echo
echo 'Architecture ' $architecture

echo 'Release: '$main_release >> /root/install.log
#Localaddresen
LOCALADDRESS="127.192.0.1/10"

actLoop=$(ifconfig | grep '^l\w*' -m 1 | cut -f1 -d ' ')
actEth=$(ifconfig | grep '^e\w*' -m 1 | cut -f1 -d ' ')
actWlan=$(ifconfig | grep '^w\w*' -m 1 | cut -f1 -d ' ')

#Internet Gateway
if [ ! -z "$1" ]  
	then
		INET_GW=$1
		remotestart=$1
	else
		INET_GW=$(ip route | grep default | cut -f3  -d ' ')
fi
INET_GW_org=$INET_GW

RESET='0'

echo
read -p 'Would you Reset the Configuration: [y/N] ' -s -n 1 RESET_ANSWER
echo
if [ "$RESET_ANSWER" = "y" ]
	then
		RESET='1'
		wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/backup-OpenWrt-2024-08-29.tar.gz
		sysupgrade -r backup-OpenWrt-2024-08-29.tar.gz
  		uci set unbound.ub_main.dhcp_link='dnsmasq'
    	uci set unbound.ub_main.listen_port='5353'
      	set_unbound_reset
  		processes=$(uci commit && reload_config)
    	wait $processes
      	processes1=$(/etc/init.d/unbound restart)
    	wait $processes1
      	processes2=$(/etc/init.d/tor restart)
    	wait $processes2
		exit 0
	else
		RESET='0'
fi

echo
read -p 'Please give me the WAN-IP (Gateway/Router): ['$INET_GW'] ' INET_GW
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
LANv6=""
IPv6=$(echo $(echo $($(echo ip addr show dev $(echo $actEth | cut -f1 -d' ')) | grep inet | cut -f6 -d ' ' ) | cut -f1 -d ' ' ) | cut -c 5-6)

if [ "$IPv6" = "::" ]
	then
		LAN=''
	else
		LANv6=$IPv6
fi

if [ "$LAN" = "" ]
    then
        LAN='192.168.1.1'
fi

LAN_org=$LAN

read -p 'Type the LAN-IP (Internal Network): ['$( echo $LAN )'] ' LAN
if [ "$LAN" = "" ]
    then
        LAN=$LAN_org
fi

if [ ! -z "$3"  ]
	then
		LOCAL_DOMAIN_org=$3
	else
		LOCAL_DOMAIN_org='CyberSecBox.local'
fi

echo
read -p  'Your local Domain of your LAN? [CyberSecBox.local] ' LOCAL_DOMAIN
if [ "$LOCAL_DOMAIN" = "" ]
	then
		LOCAL_DOMAIN=$LOCAL_DOMAIN_org
fi

if [ ! -z "$4" ]
	then
		WIFI_SSID=$4
	else
		WIFI_SSID='CyberSecBox'
fi

WIFI_SSID_org=$WIFI_SSID

echo

read -p 'The Main-WiFi-SSID? ['$(echo $WIFI_SSID)'] ' WIFI_SSID
if [ "$WIFI_SSID" = "" ]
    then
        WIFI_SSID=$WIFI_SSID_org
fi

if [ ! -z "$5" ]
	then
		WIFI_PASS=$5
	else
		WIFI_PASS='Cyber,Sec9ox'
fi

WIFI_PASS_org=$WIFI_PASS

echo

read -p 'And the WiFi-Key? [Cyber,Sec9ox] ' WIFI_PASS
if [ "$WIFI_PASS" = "" ]
	then
		WIFI_PASS=$WIFI_PASS_org
fi

USERNAME='root'
echo
read -p 'Enter the user for the login: [root] ' -s USERNAME
echo
echo
passwd $USERNAME

if [ ! -z "$6" ]
	then
		PASS=$6
	else
		PASS='Cyber,Sec9ox'
fi
if [ -n "$PASS" ]; 
	then
		(echo "$PASS"; sleep 1; echo "$PASS") | passwd > /dev/null
fi
SUBNET_sepLAN=$(echo $LAN | cut -f3 -d '.')
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

AD_GUARD='0'
echo
read -p 'Install AdGuard-Blocker? Need external USB-Device [y/N] ' -s  -n 1 ADGUARD_ACTIVE

if [ "$ADGUARD_ACTIVE" = "" ]
    then
        AD_GUARD='0'
    elif [ "$ADGUARD_ACTIVE" = "y" ]
        then
			AD_GUARD='1'
        else
            AD_GUARD='0'
fi

echo
TOR_ONION='0'
echo
read -p 'Use TOR(Onion)-Network? [Y/n] ' -s  -n 1 TOR_ACTIVE
if [ "$TOR_ACTIVE" = "" ]
	then
		TOR_ONION='1'
	elif [ "$TOR_ACTIVE" = "y" ]
 		then
			TOR_ONION='1'
 	else
		TOR_ONION='0'
fi

echo

SDNS_PORT='y'
DNSMASQ_Relay_port='53'
echo

STUBBY='1'
DNS_IP='127.0.0.1'
read -p 'DNS-Relay to STUBBY [Y/n] ' -s -n 1 SDNS_PORT


if [ "$SDNS_PORT" = "" ]
	then
		STUBBY='1'
	elif [ "$SNDS_PORT" = "y" ]
		then
			STUBBY='1'
	else
		STUBBY='0'
		DNSMASQ_relay_port='53'
		DNS_IP=$INET_GW
fi
echo $DNS_IP
echo
DNS_PORT='y'
read -p 'DNS-Relay to UNBOUND-DNS? [Y/n] ' -s  -n 1 DNS_PORT
UNBOUND='1'
if [ "$DNS_PORT" = "" ]
    then
		UNBOUND='1'
		DNSMASQ_Relay_port='5353'
		if [ "$TOR_ONION" = "1" ]
    		then
				UNBOUND_Relay_port='9053'
		elif [ "$STUBBY" = "0" ] 
   			then
    			UNBOUND_Relay_port='53'
    		else
   				UNBOUND_Relay_port='5453'
    	fi
    elif [ "$DNS_PORT" = "y" ]
		then
			UNBOUND='1'
   			DNSMASQ_Relay_port='5353'
			if [ "$TOR_ONION" = "1" ]
    			then
					UNBOUND_Relay_port='9053'    
				elif [ "$STUBBY" = "0" ] 
					then
   						UNBOUND_Relay_port='53'
				else
   					UNBOUND_Relay_port='5453'
			fi
	elif [ "$TOR_ONION" = "1" ]
    	then
	    	DNSMASQ_Relay_port='9053'
			UNBOUND_Relay_port='9053'
     		UNBOUND='0'
    elif [ "$STUBBY" = "0" ] 
		then
   			DNSMASQ_Relay_port='53'
	 		UNBOUND_Relay_port='53'
     		UNBOUND='0'
		else
    		DNSMASQ_Relay_port='5453'
			UNBOUND_Relay_port='5453'
    		UNBOUND='0'
	fi
VLAN_ENABLE='0'
echo
echo
read -p 'Would you like separate Networks for each Device-Category? [Y/n] ' -s  -n 1 VLAN_ACTIVE
if [ "$VLAN_ACTIVE" = "" ]
	then
		VLAN_ENABLE='1'
	elif [ "$VLAN_ACTIVE" = "y" ]
 		then
		VLAN_ENABLE='1'
 	else
		VLAN_ENABLE='0'
fi

echo


if [ ! -z "$7" ]
	then
		SECURE_RULESW=$7
	else
		SECURE_RULES='y'
fi

echo
read -p 'Activate HighSecure-Firewall? [Y/n] ' -s  -n 1 SECURE_RULES

if [ "$SECURE_RULES" = "" ]
        then
           FW_HSactive='1'
           #  set_HS_Firewall
        elif [ "$SECURE_RULES" = "y" ]
            then
		FW_HSactive='1'
            #    set_HS_Firewall
        else
            FW_HSactive='0'
            #  set_HS_Firewall_disable
fi

SERVER_range='192.168.'$(($SUBNET_sep - 123))'.10,192.168.'$(($SUBNET_sep - 123))'.200,24h'
CONTROL_range='192.168.'$(($SUBNET_sep - 119))'.10,192.168.'$(($SUBNET_sep - 119))'.200,24h'
HCONTROL_range='192.168.'$(($SUBNET_sep - 118))'.10,192.168.'$(($SUBNET_sep - 118))'.200,24h'
INET_range='192.168.'$SUBNET_sep'.2,192.168.'$SUBNET_sep'.200,24h'
VOICE_range='192.168.'$(($SUBNET_sep + 1))'.10,192.168.'$(($SUBNET_sep + 1))'.200,24h'
ENTERTAIN_range='192.168.'$(($SUBNET_sep - 1))'.10,192.168.'$(($SUBNET_sep - 1))'.200,24h'
GUEST_range='192.168.'$(($SUBNET_sep + 10))'.10,192.168.'$(($SUBNET_sep + 10))'.200,24h'
CMOVIE_range='192.168.'$(($SUBNET_sep + 9))'.10,192.168.'$(($SUBNET_sep + 9))'.200,24h'
TELEKOM_range='192.168.'$(($SUBNET_sep + 8))'.10,192.168.'$(($SUBNET_sep + 8))'.200,24h'
LAN_range='192.168.'$SUBNET_sepLAN'.10,192.168.'$SUBNET_sepLAN'.200,24h'

SERVER_ip='192.168.'$(($SUBNET_sep - 123))'.254'
CONTROL_ip='192.168.'$(($SUBNET_sep - 119))'.254'
HCONTROL_ip='192.168.'$(($SUBNET_sep - 118))'.254'
INET_ip='192.168.'$SUBNET_sep'.1'
VOICE_ip='192.168.'$(($SUBNET_sep + 1))'.1'
ENTERTAIN_ip='192.168.'$(($SUBNET_sep - 1))'.1'
GUEST_ip='192.168.'$(($SUBNET_sep + 10))'.1'
CMOVIE_ip='192.168.'$(($SUBNET_sep + 9))'.1'
TELEKOM_ip='192.168.'$(($SUBNET_sep + 8))'.1'
LAN_ip='192.168.'$SUBNET_sepLAN'.1'

SERVER_broadcast='192.168.'$(($SUBNET_sep - 123))'.255'
CONTROL_broadcast='192.168.'$(($SUBNET_sep - 119))'.255'
HCONTROL_broadcast='192.168.'$(($SUBNET_sep - 118))'.255'
INET_broadcast='192.168.'$SUBNET_sep'.255'
VOICE_broadcast='192.168.'$(($SUBNET_sep + 1))'.255'
ENTERTAIN_broadcast='192.168.'$(($SUBNET_sep - 1))'.255'
GUEST_broadcast='192.168.'$(($SUBNET_sep + 10))'.255'
CMOVIE_broadcast='192.168.'$(($SUBNET_sep + 9))'.255'
TELEKOM_broadcast='192.168.'$(($SUBNET_sep + 8))'.255'
LAN_broadcast='192.168.'$SUBNET_sepLAN'.255'

SERVER_lan='192.168.'$(($SUBNET_sep - 123))'.0'
CONTROL_lan='192.168.'$(($SUBNET_sep - 119))'.0'
HCONTROL_lan='192.168.'$(($SUBNET_sep - 118))'.0'
INET_lan='192.168.'$SUBNET_sep'.0'
VOICE_lan='192.168.'$(($SUBNET_sep + 1))'.0'
ENTERTAIN_lan='192.168.'$(($SUBNET_sep - 1))'.0'
GUEST_lan='192.168.'$(($SUBNET_sep + 10))'.0'
CMOVIE_lan='192.168.'$(($SUBNET_sep + 9))'.0'
TELEKOM_lan='192.168.'$(($SUBNET_sep + 8))'.0'
LAN_lan='192.168.'$SUBNET_sepLAN'.0'

SERVER_net=$SERVER_ip'/24'
CONTROL_net=$CONTROL_ip'/24'
HCONTROL_net=$HCONTROL_ip'/24'
INET_net=$INET_ip'/24'
VOICE_net=$VOICE_ip'/24'
ENTERTAIN_net=$ENTERTAIN_ip'/24'
GUEST_net=$GUEST_ip'/24'
CMOVIE_net=$CMOVIE_ip'/24'
TELEKOM_net=$TELEKOM_ip'/24'
WAN_net=$WAN_ip'/24'
WAN_MOBILE_net=$WAN_MOBILE_ip'/24'
LAN_net=$LAN_ip'/24'

SERVER_domain='server.'$LOCAL_DOMAIN
CONTROL_domain='control.'$LOCAL_DOMAIN
HCONTROL_domain='hcontrol.'$LOCAL_DOMAIN
INET_domain='inet.'$LOCAL_DOMAIN
VOICE_domain='voice.local'
ENTERTAIN_domain='entertain.local'
GUEST_domain='guest.local'
CMOVIE_domain='cmovie.local'
TELEKOM_domain='telekom.local'
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

clear
view_config

define_variables() {
#----------------------------------------------------------------------------
echo
echo 'define variables'
echo
#
DHCP_port="67"
all_other_DHCP_port="1-66 68-65535"


#Printer_LPR_IPP
Printer_port="515 631 9100"
all_other_Printer_port="1-514 516-630 632-9099 9101-65535"

#NTP
NTP_port="123"
all_other_NTP_port="1-122 124-65535"

#NFS
NFS_port="2049"
all_other_NFS_port="1-2048 2050-65535"

#AFP
AFP_port="548"
all_other_AFP_port="1-547 549-65535"

#SMB
SMB_port="137 138 139 445"
all_other_SMB_port="1-444 446-136 140-65535"

#VPN
VPN_port="500 4500"
all_other_VPN_port="1-499 501-4499 4501-65535"

#Open Directory Proxy (ODProxy)
ODProxy_port="625"
all_other_ODProxy_port="1-624 266-65535"

#Syslog
#UDP
#514
Syslog_port="514"
all_other_Syslog_port="1-513 515-65535"

#NetBIOS
#UDP
#138
NetBIOS_port="138"
all_other_NetBIOS_port="1-137 139-65535"

#WINS
#137
WINS_port="137"
all_other_WINS_port="1-136 138-65535"

#Simple Service Discovery Protocol (SSDP)
#UDP
#1900
SSDP_port="1900"
all_other_SSDP_port="1-1899 1901-65535"

#Web Services Dynamic Discovery (WS-Discovery)
#UDP
#3702
WS_Discovery_port="5357 3702"
all_other_WS_Discovery_port="1-5356 5358-3701 3703-65535"

#Port Control Protocol (PCP)
#5351
PCP_port="5351"
all_other_PCP_port="1-5350 3552-65535"

#Port NETWORK Controler
#8043
CONTROLER_port="8043"
all_other_CONTROLER_port="1-8042 8044-65535"

#Multicast Domain Name Service (mDNS)
#5353
mDNS_port="5353"
all_other_mDNS_port="1-5352 5354-65535"

#Link Local Multicast Name Resolution (LLMNR)
#5357
LLMNR_port="5357"
all_other_LLMNR_port="1-5356 5358-65535"

#Telefonie (SIP)
#5060
SIP_port="5060"
all_other_SIP_port="1-5059 5061-65535"

#Telefonie (RTP, RTCP)
#7077-7097
RTP_RTCP_port="7077-7097"
all_other_RTP_RTCP_port="1-7076 7098-65535"

#Telefonie (SIP, RTP, RTCP)
#7077-7097
SIP_RTP_RTCP_port="5060 7077-7097"
all_other_SIP_RTP_RTCP_port="1-5059 5061-7076 7098-65535"

#FRITZ!Box
AVM_port="8181-8186"
all_other_AVM_port="1-8180 8187-65535"

#FRITZ!Box MESH
AVM_Mesh_port="50842 53805"
all_other_AVM_Mesh_port="1-50841 50843-53804 53806-65535"

#Torrc Ports
TORRC_port="9030 9040 9049 9050 9053 9060 9100 9150 9200"
all_other_TORRC_port="1-9029 9031-9039 9041-9048 9051 9052 9054-9059 9061-9099 9101-9049 9051-9199 9201-65535"


#SPYPE
Skype_port="1000-10000 16000-26000 38562 50000-65000"
all_other_Skype_port="1-999 10001-15999 26001-38561 38563-49999 65001-65535"
Skype_udp_port="38562 3478-3481 50000-60000"
all_other_Skype_udp_port="1-3477 3482-38561 38563-49999 60000-65535"

#MSRDP_Alexa Call (Ports)
#3389
MSRDP_AlexaCall_port="3389"
all_other_MSRDP_AlexaCall_port="1-3388 3390-65535"

#HTTP_s (Ports)
#80, 443, 8080
HTTP_s_port="80 443 8080"
HTTPs_port="443"
HTTP_port="80"
all_other_HTTP_s_port="1-79 81-442 444-8079 8081-65535"

#FTP_Server
FTP_port="20 21"
all_other_FTP_port="1-19 22-65535"

#Remote_Acces_http(s)
#40443-40446
Acces_http_port="40443-40446"
all_other_Acces_http_port="1-40442 40447-65535"

#eMule (Ports)
#4662, 4672
eMule_port="4662 4672"
all_other_eMule_port="1-4661 4663-4671 4673-65535"

#Bittorrent (Ports)
#6881-6999
Bittorrent_port="6881-6999"
all_other_Bittorrent_port="1-6880 7000-65535"

#DNS
DNS_port="53"
all_other_DNS_port="1-52 54-65535"

#Tor_dns
DNS_TOR_port="9053"
all_other_DNS_TOR_port="1-9052 9054-65535"

#DNS Crypt
DNS_CRYPT_port="5300"
all_other_DNS_CRYPT_port="1-5299 5301-65535"

#DNS Stubby
DNS_STUBBY_port="5453"
all_other_DNS_STUBBY_port="1-5452"5454-65535

#DNS_UNBOUND
DNS_UNBOUND_port="5353"
all_other_DNS_UNBOUND_port="1-5352 5354-65535"

#SDNS
SDNS_port="853"
all_other_SDNS_port="1-852 854-65535"

#allDNS Ports
all_DNS_port="53 853 5300 5353 5453 9053 33216 34885 35113 35141 37572 38700 39354 41227 41287 41675 43609 47535 48427 48736 48777 50275 54715 54789 51465 56343 56534 57687 60870"
all_other_all_DNS_port="1-52 54-852 854-5299 5301-5352 5354-5452 5454-9052 9054-33215 33217- 34884 34886-35112 35114-35140 35142-37571 37573-38699 38701-39353 39355-41226 41227-41286 41288-41674 41676-43608 43610-47534 47536-48426 48428-48735 48737-48776 48778-50274 50276-54714 54716-54788 54790-51464 51466-56342 56344-56533 56535-57686 57688-60869 60871-65535"

#NTOPNG Port
#NTOPNG_PORT="3000"
NTOPNG_port="3000"
all_other_NTOPNG_port="1-2999 3001-65535"

#Privoxy Port
#PRIVOXY_PORT="8188"
PRIVOXY_port="8188"
all_other_PRIVOXY_port="1-8187 8189-65535"

#PiHole Port
#PIHOLE_PORT="81"
#PIHOLE_FTL_PORT="4711"
#PiHole Port
PIHOLE_port="81"
PIHOLE_FTL_port="4711"
all_PIHOLE_port="81 4711"
all_other_PIHOLE_port="1-80 82-65535"
all_other_PIHOLE_FTL_port="1-4710 4712-65535"
all_othjer_all_PIHOLE_port="1-80 82-4710 4712-65535"

#Real Time Streaming Protocol (RTSP)
#"554"
RTSP_port="554"
all_other_RTSP_port="1-553 555-65535"

#NNTP
#"119"
NNTP_port="119"
all_other_NNTP_port="1-118 120-65535"

#RPC
RPC_port="111"
all_other_RPC_port="1-110 112-65535"

#LDAP
#"389 636"
LDAP_port="389 636"
all_other_LDAP_port="1-388 390-635 637-65535"

#Password_Server
#"106"
PASSWDSRV_port="106"
all_other_PASSWDSRV_port="1-105 107-65535"

#KERBEROS
#"88 749"
KERBEROS_port="88 749"
all_other_KERBEROS_port="1-87 89-748 750-65535"

#IMAP4 Port
#IMAP_PORT="143 993 626"
IMAP_port="143 993 626"
all_other_IMAP_port="1-142 144-992 994-625 627-65535"

#POP3 Port
#POP3_PORT="110 995"
POP3_port="110 995"
all_other_POP3_port="1-109 111-994 996-65535"

#smtp
#"25 465 587"
SMTP_port="25 465 587"
all_other_SMTP_port="1-24 26-464 466-586 588-65535"

#all Email
email_port="25 110 143 465 587 626 993 995"
all_other_email_port="1-24 26-109 111-142 144-464 466-586 588-625 627-992 994 996-65535"

#NTP
#123
NTP_port="123"
all_other_NTP_port="1-122 124-65535"

#SSH_SFTP (Port)
#22
SSH_port="22"
all_other_SSH_port="1-21 23-65535"

#Telnet (Port)
#23
TELNET_port="23"
all_other_TELNET_port="1-22 24-65535"

#Telnet_SSH_SFTP
#22 23
TELNET_SSH_port="22 23"
all_other_TELNET_SSH_port="1-21 24-65535"

#OPENWRT GUI ACCESS_PORT
ACCESS_HTTP_port="8080"
ACCESS_HTTPS_port="8443"

#TOR Onion Services
TOR_SOCKS_port="9050"
TOR_SOCKS2_port="9150"
TOR_TRANS_port="9040"
TOR_DIR_port="9030"
TOR_OR_port="9049"
TOR_THTTP_port="9060"

#Amazon_Alexa
Amazon_Alexa_port="67-68 8080 40317 49317 33434 123 54838 55443 46053 1000-10000 50000-65000 16000-26000"
all_other_Amazon_Alexa_port='1-24 26-52 54-66 69-79 81-99 101-122 124-442 444-852 854-999 1001-15999 26001-33433 33435-34083 34084-40316 40318-41906 41909-46052 46054-46077 46079-49316 49318-49999 65001-65535'
Amazon_Alexa_UDP_port="4070 5353 40317 49317 33434 50000-60000 3478-3481"
all_other_Amazon_Alexa_UDP_port="1-52 54-66 69-122 124-852 854-1899 1901-3477 3482-4069 4071 4073-4171 4173-5352 5354-5452 5454-33433 33435-40316 40318-49316 49318-49999"

#Office_Client (Port)
# 21 22 25 53 67 80 110 123 139 138 137 443 445 515 548 631 853 2049 5353 9030 9040 9049 9050 9053 9060 9100 50275 54715 54789 51465 56343 56534 57687 60870
OfficeClient_port="21 22 25 53 67 80 110 123 139 138 137 443 445 515 548 631 853 2049 5353 9030 9040 9049 9050 9053 9060 9100 50275 54715 54789 51465 56343 56534 57687 60870"
all_other_OfficeClient_port='1-20 24 26-52 54-66 68-79 81-109 111-122 124-136 140-442 444 446-514 516-547 549-630 632-852 854-2048 2050-5352 5354-8442 8444-9029 9031-9039 9041-9048 9051 9052 9054-9059 9061-9099 9101-40442 40446-50274 50276-51464 51465-54714 54716-54788 54790-56342 56344-56533 56535-57686 57688-60869 60871-65535'

OfficeWebClient_port="21 22 25 53 80 110 123 443 853 5353 9030 9040 9049 9050 9053 9060 50275 54715 54789 51465 56343 56534 57687 60870"
all_other_OfficeWebClient_port='1-20 23 24 26-52 54-79 81-109 111-122 124-442 444-852 854-5299 5301-5352 5354-5452 5454-8079 8081-8442 8444-9029 9031-9039 9041-9049 9051 9052 9054-9059 9061-40274 40276-40442 40446-51464 51466-54714 54716-54788 54790-56342 56344-56533 56535-57686 57688-60869 60871-65535'

#Only_WebClient
all_other_WebClient_port='1-20 23 24 26-52 54-79 81-109 111-122 124-442 444-852 854-5352 5354-5452 5454-8079 8081-8442 8444-9029 9031-9039 9041-9049 9051 9052 9054-9059 9061-40274 40276-40442 40446-51464 51466-54714 54716-54788 54790-56342 56344-56533 56535-57686 57688-60869 60871-65535'
WebClient_port="21 22 25 53 80 110 123 443 853 5353 5453 8080 8443 9030 9040 9049 9050 9053 9060 40275 40443 40444 40445 51465 54715 54789 56343 56534 567687 60870"

#UPNP
UPNP_port="49000"
all_other_UPMP_port="1-48999 49001-65535"

#Block_Incoming
all_proto="esp gre icmp igmp tcp udp"

#Block all other Protocols
all_other_porto="esp gre igmp"

#Block_EXT_HEIGHT_PORT_UDP
all_other_EXT_HEIGHT_PORT_UDP_port="9061-33433 33435-40316 40318-49316 49318-65535"
EXT_HEIGHT_PORT_UDP_port="33434 40317 49317"

#Block_EXT_HEIGHT_PORT
all_other_EXT_HEIGHT_PORT_port="10000-33433 33435-40316 40318-49316 49318-54837 54839-65535"
EXT_HEIGHT_PORT_port="33434 40317 49317 54838"

#-------------------------------------------------------------------------
iptab_DHCP_port="67"
iptab_all_other_DHCP_port="1:66 68:65535"


#Printer_LPR_IPP
iptab_Printer_port="515 631 9100"
iptab_all_other_Printer_port="1:514 516:630 632:9099 9101:65535"

#NTP
iptab_NTP_port="123"
iptab_all_other_NTP_port="1:122 124:65535"

#NFS
iptab_NFS_port="2049"
iptab_all_other_NFS_port="1:2048 2050:65535"

#AFP
iptab_AFP_port="548"
iptab_all_other_AFP_port="1:547 549:65535"

#SMB
iptab_SMB_port="137 138 139 445"
iptab_all_other_SMB_port="1:444 446:136 140:65535"

#VPN
iptab_VPN_port="500 4500"
iptab_all_other_VPN_port="1:499 501:4499 4501:65535"

#Open Directory Proxy (ODProxy)
iptab_ODProxy_port="625"
iptab_all_other_ODProxy_port="1:624 266:65535"

#Syslog
#UDP
#514
iptab_Syslog_port="514"
iptab_all_other_Syslog_port="1:513 515:65535"

#NetBIOS
#UDP
#138
iptab_NetBIOS_port="138"
iptab_all_other_NetBIOS_port="1:137 139:65535"

#WINS
#137
iptab_WINS_port="137"
iptab_all_other_WINS_port="1:136 138:65535"

#Simple Service Discovery Protocol (SSDP)
#UDP
#1900
iptab_SSDP_port="1900"
iptab_all_other_SSDP_port="1:1899 1901:65535"

#Web Services Dynamic Discovery (WS:Discovery)
#UDP
#3702
iptab_WS_Discovery_port="5357 3702"
iptab_all_other_WS_Discovery_port="1:5356 5358:3701 3703:65535"

#Port Control Protocol (PCP)
#5351
iptab_PCP_port="5351"
iptab_all_other_PCP_port="1:5350 3552:65535"

#Port NETWORK Controler
#8043
iptab_CONTROLER_port="8043"
iptab_all_other_CONTROLER_port="1:8042 8044:65535"

#Multicast Domain Name Service (mDNS)
#5353
iptab_mDNS_port="5353"
iptab_all_other_mDNS_port="1:5352 5354:65535"

#Link Local Multicast Name Resolution (LLMNR)
#5357
iptab_LLMNR_port="5357"
iptab_all_other_LLMNR_port="1:5356 5358:65535"

#Telefonie (SIP)
#5060
iptab_SIP_port="5060"
iptab_all_other_SIP_port="1:5059 5061:65535"

#Telefonie (RTP, RTCP)
#7077:7097
iptab_RTP_RTCP_port="7077:7097"
iptab_all_other_RTP_RTCP_port="1:7076 7098:65535"

#Telefonie (SIP, RTP, RTCP)
#7077:7097
iptab_SIP_RTP_RTCP_port="5060 7077:7097"
iptab_all_other_SIP_RTP_RTCP_port="1:5059 5061:7076 7098:65535"

#FRITZ!Box
iptab_AVM_port="8181:8186"
iptab_all_other_AVM_port="1:8180 8187:65535"

#FRITZ!Box MESH
iptab_AVM_Mesh_port="50842 53805"
iptab_all_other_AVM_Mesh_port="1:50841 50843:53804 53806:65535"

#Torrc Ports
iptab_TORRC_port="9030 9040 9049 9050 9053 9060 9100 9150 9200"
iptab_all_other_TORRC_port="1:9029 9031:9039 9041:9048 9051 9052 9054:9059 9061:9099 9102:9149 9151:9199 9201:65535"



#SPYPE
iptab_Skype_port="1000:10000 16000:26000 38562 50000:65000"
iptab_all_other_Skype_port="1:999 10001:15999 26001:38561 38563:49999 65001:65535"
iptab_Skype_udp_port="38562 3478:3481 50000:60000"
iptab_all_other_Skype_udp_port="1:3477 3482:38561 38563:49999 60000:65535"

#MSRDP_Alexa Call (Ports)
#3389
iptab_MSRDP_AlexaCall_port="3389"
iptab_all_other_MSRDP_AlexaCall_port="1:3388 3390:65535"

#HTTP_s (Ports)
#80, 443, 8080
iptab_HTTP_s_port="80 443 8080"
iptab_HTTPs_port="443"
iptab_HTTP_port="80"
iptab_all_other_HTTP_s_port="1:79 81:442 444:8079 8081:65535"

#FTP_Server
iptab_FTP_port="20 21"
iptab_all_other_FTP_port="1:19 22:65535"

#Remote_Acces_http(s)
#40443:40446
iptab_Acces_http_port="40443:40446"
iptab_all_other_Acces_http_port="1:40442 40447:65535"

#eMule (Ports)
#4662, 4672
iptab_eMule_port="4662 4672"
iptab_all_other_eMule_port="1:4661 4663:4671 4673:65535"

#Bittorrent (Ports)
#6881:6999
iptab_Bittorrent_port="6881:6999"
iptab_all_other_Bittorrent_port="1:6880 7000:65535"

#Tor_dns
iptab_DNS_TOR_port="9053"
iptab_all_other_DNS_TOR_port="1:9052 9054:65535"

#DNS Crypt
iptab_DNS_CRYPT_port="5300"
iptab_all_other_DNS_CRYPT_port="1:5299 5301:65535"

#DNS Stubby
iptab_DNS_STUBBY_port="5453"
iptab_all_other_DNS_STUBBY_port="1:5452"5454:65535

#DNS_UNBOUND
iptab_DNS_UNBOUND_port="5353"
iptab_all_other_DNS_UNBOUND_port="1:5352 5354:65535"

#SDNS
iptab_SDNS_port="853"
iptab_all_other_SDNS_port="1:852 854:65535"

#allDNS Ports
iptab_all_DNS_port="53 853 5300 5353 5453 9053 33216 34885 35113 35141 37572 38700 39354 41227 41287 41675 43609 47535 48427 48736 48777 50275 54715 54789 51465 56343 56534 57687 60870"
iptab_all_other_all_DNS_port="1:52 54:852 854:5299 5301:5352 5354:5452 5454:9052 9054:33215 33217: 34884 34886:35112 35114:35140 35142:37571 37573:38699 38701:39353 39355:41226 41227:41286 41288:41674 41676:43608 43610:47534 47536:48426 48428:48735 48737:48776 48778:50274 50276:54714 54716:54788 54790:51464 51466:56342 56344:56533 56535:57686 57688:60869 60871:65535"

#NTOPNG Port
#NTOPNG_PORT="3000"
iptab_NTOPNG_port="3000"
iptab_all_other_NTOPNG_port="1:2999 3001:65535"

#Privoxy Port
#PRIVOXY_PORT="8188"
iptab_PRIVOXY_port="8188"
iptab_all_other_PRIVOXY_port="1:8187 8189:65535"

#PiHole Port
#PIHOLE_PORT="81"
#PIHOLE_FTL_PORT="4711"
#PiHole Port
iptab_PIHOLE_port="81"
iptab_PIHOLE_FTL_port="4711"
iptab_all_PIHOLE_port="81 4711"
iptab_all_other_PIHOLE_port="1:80 82:65535"
iptab_all_other_PIHOLE_FTL_port="1:4710 4712:65535"
iptab_all_othjer_all_PIHOLE_port="1:80 82:4710 4712:65535"

#Real Time Streaming Protocol (RTSP)
#"554"
iptab_RTSP_port="554"
iptab_all_other_RTSP_port="1:553 555:65535"

#NNTP
#"119"
iptab_NNTP_port="119"
iptab_all_other_NNTP_port="1:118 120:65535"

#RPC
iptab_RPC_port="111"
iptab_all_other_RPC_port="1:110 112:65535"

#LDAP
#"389 636"
iptab_LDAP_port="389 636"
iptab_all_other_LDAP_port="1:388 390:635 637:65535"

#Password_Server
#"106"
iptab_PASSWDSRV_port="106"
iptab_all_other_PASSWDSRV_port="1:105 107:65535"

#KERBEROS
#"88 749"
iptab_KERBEROS_port="88 749"
iptab_all_other_KERBEROS_port="1:87 89:748 750:65535"

#IMAP4 Port
#IMAP_PORT="143 993 626"
iptab_IMAP_port="143 993 626"
iptab_all_other_IMAP_port="1:142 144:992 994:625 627:65535"

#POP3 Port
#POP3_PORT="110 995"
iptab_POP3_port="110 995"
iptab_all_other_POP3_port="1:109 111:994 996:65535"

#smtp
#"25 465 587"
iptab_SMTP_port="25 465 587"
iptab_all_other_SMTP_port="1:24 26:464 466:586 588:65535"

#all Email
iptab_email_port="25 110 143 465 587 626 993 995"
iptab_all_other_email_port="1:24 26:109 111:142 144:464 466:586 588:625 627:992 994 996:65535"

#NTP
#123
iptab_NTP_port="123"
iptab_all_other_NTP_port="1:122 124:65535"

#SSH_SFTP (Port)
#22
iptab_SSH_port="22"
iptab_all_other_SSH_port="1:21 23:65535"

#Telnet (Port)
#23
iptab_TELNET_port="23"
iptab_all_other_TELNET_port="1:22 24:65535"

#Telnet_SSH_SFTP
#22 23
iptab_TELNET_SSH_port="22 23"
iptab_all_other_TELNET_SSH_port="1:21 24:65535"

#OPENWRT GUI ACCESS_PORT
iptab_ACCESS_HTTP_port="8080"
iptab_ACCESS_HTTPS_port="8443"

#TOR Onion Services
iptab_TOR_SOCKS_port="9050"
iptab_TOR_SOCKS2_port="9150"
iptab_TOR_TRANS_port="9040"
iptab_TOR_DIR_port="9030"
iptab_TOR_OR_port="9049"
iptab_TOR_THTTP_port="9060"


#Amazon_Alexa
iptab_Amazon_Alexa_port="67:68 8080 40317 49317 33434 123 54838 55443 46053 1000:10000 50000:65000 16000:26000"
iptab_all_other_Amazon_Alexa_port='1:24 26:52 54:66 69:79 81:99 101:122 124:442 444:852 854:999 1001:15999 26001:33433 33435:34083 34084:40316 40318:41906 41909:46052 46054:46077 46079:49316 49318:49999 65001:65535'
iptab_Amazon_Alexa_UDP_port="4070 5353 40317 49317 33434 50000:60000 3478:3481"
iptab_all_other_Amazon_Alexa_UDP_port="1:52 54:66 69:122 124:852 854:1899 1901:3477 3482:4069 4071 4073:4171 4173:5352 5354:5452 5454:33433 33435:40316 40318:49316 49318:49999"

#Office_Client (Port)
# 21 22 25 53 67 80 110 123 139 138 137 443 445 515 548 631 853 2049 5353 9030 9040 9049 9050 9053 9060 9100 50275 54715 54789 51465 56343 56534 57687 60870
iptab_OfficeClient_port="21 22 25 53 67 80 110 123 139 138 137 443 445 515 548 631 853 2049 5353 9030 9040 9049 9050 9053 9060 9100 50275 54715 54789 51465 56343 56534 57687 60870"
iptab_all_other_OfficeClient_port='1:20 24 26:52 54:66 68:79 81:109 111:122 124:136 140:442 444 446:514 516:547 549:630 632:852 854:2048 2050:5352 5354:8442 8444:9029 9031:9039 9041:9048 9051 9052 9054:9059 9061:9099 9101:40442 40446:50274 50276:51464 51465:54714 54716:54788 54790:56342 56344:56533 56535:57686 57688:60869 60871:65535'

iptab_OfficeWebClient_port="21 22 25 53 80 110 123 443 853 5353 9030 9040 9049 9050 9053 9060 50275 54715 54789 51465 56343 56534 57687 60870"
iptab_all_other_OfficeWebClient_port='1:20 23 24 26:52 54:79 81:109 111:122 124:442 444:852 854:5299 5301:5352 5354:5452 5454:8079 8081:8442 8444:9029 9031:9039 9041:9049 9051 9052 9054:9059 9061:40274 40276:40442 40446:51464 51466:54714 54716:54788 54790:56342 56344:56533 56535:57686 57688:60869 60871:65535'

#Only_WebClient
iptab_all_other_WebClient_port='1:20 23 24 26:52 54:79 81:109 111:122 124:442 444:852 854:5352 5354:5452 5454:8079 8081:8442 8444:9029 9031:9039 9041:9049 9051 9052 9054:9059 9061:40274 40276:40442 40446:51464 51466:54714 54716:54788 54790:56342 56344:56533 56535:57686 57688:60869 60871:65535'
iptab_WebClient_port="21 22 25 53 80 110 123 443 853 5353 5453 8080 8443 9030 9040 9049 9050 9053 9060 40275 40443 40444 40445 51465 54715 54789 56343 56534 567687 60870"

#UPNP
iptab_UPNP_port="49000"
iptab_all_other_UPMP_port="1:48999 49001:65535"

#Block_EXT_HEIGHT_PORT_UDP
iptab_all_other_EXT_HEIGHT_PORT_UDP_port="9061:33433 33435:40316 40318:49316 49318:65535"
iptab_EXT_HEIGHT_PORT_UDP_port="33434 40317 49317"

#Block_EXT_HEIGHT_PORT
iptab_all_other_EXT_HEIGHT_PORT_port="10000:33433 33435:40316 40318:49316 49318:54837 54839:65535"
iptab_EXT_HEIGHT_PORT_port="33434 40317 49317 54838"


#Block public DNS Server
DNS_EXT_BLOCK1_SVR="8.8.8.8" 
DNS_EXT_BLOCK2_SVR="8.8.4.4"
DNS_EXT_BLOCK3_SVR="9.9.9.9" 
DNS_EXT_BLOCK4_SVR="149.112.112.112" 
DNS_EXT_BLOCK5_SVR="9.9.9.10" 
DNS_EXT_BLOCK6_SVR="9.9.9.11" 
DNS_EXT_BLOCK7_SVR="9.9.9.12" 
DNS_EXT_BLOCK8_SVR="149.112.112.10" 
DNS_EXT_BLOCK9_SVR="149.112.112.11" 
DNS_EXT_BLOCK10_SVR="208.67.222.222" 
DNS_EXT_BLOCK11_SVR="208.67.220.220" 
DNS_EXT_BLOCK12_SVR="2001:4860:4860::8888" 
DNS_EXT_BLOCK13_SVR="2001:4860:4860::8844" 
DNS_EXT_BLOCK14_SVR="2620:fe::fe" 
DNS_EXT_BLOCK15_SVR="2620:fe::9" 
DNS_EXT_BLOCK16_SVR="2620:fe::11" 
DNS_EXT_BLOCK17_SVR="2620:fe::fe:11"
DNS_EXT_BLOCK18_SVR="2620:fe::10" 
DNS_EXT_BLOCK19_SVR="2620:fe::fe:10"

#Cloudflare_DNS_Server
DNS_Cloudflare1_SVR="1.1.1.1" 
DNS_Cloudflare2_SVR="1.1.1.2"
DNS_Cloudflare3_SVR="1.1.1.3"
DNS_Cloudflare4_SVR="1.0.0.1" 
DNS_Cloudflare5_SVR="1.0.0.2"
DNS_Cloudflare6_SVR="1.0.0.3"  
DNS_Cloudflare7_SVR="2606:4700:4700::1111" 
DNS_Cloudflare8_SVR="2606:4700:4700::1112" 
DNS_Cloudflare9_SVR="2606:4700:4700::1113"
DNS_Cloudflare10_SVR="2606:4700:4700::1001" 
DNS_Cloudflare11_SVR="2606:4700:4700::1002" 
DNS_Cloudflare12_SVR="2606:4700:4700::1003"  
DNS_Cloudflare13_SVR=$SERVER_ip
DNS_Cloudflare14_SVR=$CONTROL_ip
DNS_Cloudflare15_SVR=$HCONTROL_ip
DNS_Cloudflare16_SVR=$INET_ip
DNS_Cloudflare17_SVR=$VOICE_ip
DNS_Cloudflare18_SVR=$ENTERTAIN_ip
DNS_Cloudflare19_SVR=$GUEST_ip
DNS_Cloudflare20_SVR="127.0.0.1" 
DNS_Cloudflare21_SVR="127.0.10.1" 
DNS_Cloudflare22_SVR="0::1"
DNS_Cloudflare23_SVR="dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion"  

#Cloudflare Onion TOR
CLOUDFLARE="dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion"

#Tor Netzwerk
TOR_ROUTING="10.192.0.0/10"

# destinations you don't want routed through Tor
NON_TOR="$WAN_net $INET_net $SERVER_net $CONTROL_net $HCONTROL_net $VOICE_net $ENTERTAIN_net $GUEST_net" 
# s3-1-w.amazonaws.com 52.192.0.0/11 .ix.nflxvideo.net joyn.de joyn.net hvb.de hypovereinsbank.de"

# TV and VoD
JOYN_SVR=""
ZATTOO_SVR=""
WAYPU_SVR=""
PRIME_SVR=""
NETFLIX_SRV="54.204.25.0/28 23.23.189.144/28 34.195.253.0/25 35.163.200.168/28"
VIDEO_SRV="52.192.0.0/11 99.86.3.59/24 18.236.7.30/11 217.148.99.11/28 46.137.171.215/11 34.241.244.104/24 207.45.72.215/11 "$NETFLIX_SRV

echo
echo 'variables defineds'
echo
}


view_config()  {
echo >> /root/install.log
echo
echo 'Your Config is:'
echo
echo 'DNS-Server:           '$DNS_IP
echo
echo 'DNS-Relay Port:       '$DNSMASQ_Relay_port
echo 'Tor/Onion:            '$TOR_ONION
echo 'Firewall:             '$FW_HSactive
echo
echo 'Client-WiFi SSID:     '$INET_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$INET_net
echo
echo 'Smarthome-WiFi SSID:  '$HCONTROL_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$HCONTROL_net
echo
echo 'Voice-Assistent SSID: '$VOICE_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$VOICE_net
echo
echo 'Smart-TV/-DVD SSID:   '$ENTERTAIN_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$ENTERTAIN_net
echo
echo 'Server-WiFi SSID:     '$SERVER_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$SERVER_net
echo
echo 'IR/BT-Control SSID:   '$CONTROL_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$CONTROL_net
echo
echo 'Guests SSID is:       '$GUEST_ssid
echo 'Key:                  '$WIFI_PASS
echo 'IP:                   '$GUEST_net
echo
echo 'IP-Address:           '$WAN_ip
echo 'Gateway:              '$INET_GW
echo 'Domain:               '$LOCAL_DOMAIN
echo
echo 'GUI-Access:           https://'$INET_ip':8443'
echo 'User:                 '$USERNAME
echo 'Password:             password'
echo
echo 'Please wait for at least 10 minutes and then it will reboot ...'
echo
}

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

	sleep 40
	out=$(wget --waitretry=10 -t 5 -O "/root/$OUTPUT_FILE" "$URL")
    wait $out
	echo $out >> /root/install_customice.log
	 if [[ $? -eq 0 ]]; then
    	if check_hash "$OUTPUT_FILE"; then
        	echo "Hash is okay"  >> /root/install_customice.log
        	break
    	else
       		echo "$OUTPUT_FILE" | sha256sum >> /root/install_customice.log
        	#rm -f "$OUTPUT_FILE" && echo 'del file false Hash' >> /root/install_customice.log
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
		process50=$(wget --waitretry=10 -t 5 -O /root/openWRT23_install.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh)
    	wait $process50 && echo 'download retry openWRT23_install.sh' >> /root/install_customice.log

		if [ "$(ls /www/luci-static/bootstrap/logo.svg)" != "" ]
			then
				processe53s=$(rm /www/luci-static/bootstrap/logo*.* >> /root/install_customice.log)
    			wait $processes53 && echo 'delete logo.svg' >> /root/install_customice.log
		fi
		ls /root/ -Rlha >> /root/install_customice.log
		process=$(check_download "https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh" "b86e524d522def9ee4f032667f2bff088e3a185a1e8cfe3f7e663fae98af8022" "openWRT23_install.sh")
		wait $process && echo 'download openWRT23_install.sh' >> /root/install_customice.log
		ls /root/ -Rlha >> /root/install_customice.log
		echo >> /root/install_customice.log
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
	/etc/init.d/uhttpd restart  >> /root/install_customice.log	
	/etc/init.d/network restart  >> /root/install_customice.log
	echo 'On Error enter logread'
	echo

}

set_tor() {

/etc/init.d/tor stop >> /root/install.log
/etc/init.d/log restart >> /root/install.log

echo
if grep -q 'ContactInfo C' /etc/tor/torrc	
	then
		echo 'The Tor-Setup is done at least'
	else
		set_tor_sub
fi
echo

 }

set_tor_sub() {
# Configure Tor client

echo 'Start Tor-Setup'

cat << EOF > /etc/tor/torrc

## Configuration file for a typical Tor user
## Last updated 28 February 2019 for Tor 0.3.5.1-alpha.
## (may or may not work for much older or much newer versions of Tor.)
##
## Lines that begin with "## " try to explain what's going on. Lines
## that begin with just "#" are disabled commands: you can enable them
## by removing the "#" symbol.
##
## See 'man tor', or https://www.torproject.org/docs/tor-manual.html,
## for more options you can use in this file.
##
## Tor will look for this file in various places based on your platform:
## https://support.torproject.org/tbb/tbb-editing-torrc/

## Tor opens a SOCKS proxy on port 9050 by default -- even if you don't
## configure one below. Set "SOCKSPort 0" if you plan to run Tor only
## as a relay, and not make any local application connections yourself.
#SOCKSPort 9050 # Default: Bind to localhost:9050 for local connections.
#SOCKSPort 192.168.0.1:9100 # Bind to this address:port too.

## Entry policies to allow/deny SOCKS requests based on IP address.
## First entry that matches wins. If no SOCKSPolicy is set, we accept
## all (and only) requests that reach a SOCKSPort. Untrusted users who
## can access your SOCKSPort may be able to learn about the connections
## you make.
#SOCKSPolicy accept 192.168.0.0/16
#SOCKSPolicy accept6 FC00::/7
#SOCKSPolicy reject *

## Logs go to stdout at level "notice" unless redirected by something
## else, like one of the below lines. You can have as many Log lines as
## you want.
##
## We advise using "notice" in most cases, since anything more verbose
## may provide sensitive information to an attacker who obtains the logs.
##
## Send all messages of level 'notice' or higher to /var/log/tor/notices.log
#Log notice file /var/log/tor/notices.log
## Send every possible message to /var/log/tor/debug.log
#Log debug file /var/log/tor/debug.log
## Use the system log instead of Tor's logfiles
Log notice syslog
## To send all messages to stderr:
#Log debug stderr

## Uncomment this to start the process in the background... or use
## --runasdaemon 1 on the command line. This is ignored on Windows;
## see the FAQ entry if you want Tor to run as an NT service.
#RunAsDaemon 1

## The directory for keeping all the keys/etc. By default, we store
## things in $HOME/.tor on Unix, and in Application Data\tor on Windows.
DataDirectory /var/lib/tor

## The port on which Tor will listen for local connections from Tor
## controller applications, as documented in control-spec.txt.
#ControlPort 9051
## If you enable the controlport, be sure to enable one of these
## authentication methods, to prevent attackers from accessing it.
#HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
#CookieAuthentication 1

############### This section is just for location-hidden services ###

## Once you have configured a hidden service, you can look at the
## contents of the file ".../hidden_service/hostname" for the address
## to tell people.
##
## HiddenServicePort x y:z says to redirect requests on port x to the
## address y:z.

#HiddenServiceDir /var/lib/tor/hidden_service/
#HiddenServicePort 80 127.0.0.1:80

#HiddenServiceDir /var/lib/tor/other_hidden_service/
#HiddenServicePort 80 127.0.0.1:80
#HiddenServicePort 22 127.0.0.1:22

################ This section is just for relays #####################
#
## See https://community.torproject.org/relay for details.

## Required: what port to advertise for incoming Tor connections.
#ORPort 9001
## If you want to listen on a port other than the one advertised in
## ORPort (e.g. to advertise 443 but bind to 9090), you can do it as
## follows.  You'll need to do ipchains or other port forwarding
## yourself to make this work.
#ORPort 443 NoListen
#ORPort 127.0.0.1:9090 NoAdvertise
## If you want to listen on IPv6 your numeric address must be explicitly
## between square brackets as follows. You must also listen on IPv4.
#ORPort [2001:DB8::1]:9050

## The IP address or full DNS name for incoming connections to your
## relay. Leave commented out and Tor will guess.
#Address noname.example.com

## If you have multiple network interfaces, you can specify one for
## outgoing traffic to use.
## OutboundBindAddressExit will be used for all exit traffic, while
## OutboundBindAddressOR will be used for all OR and Dir connections
## (DNS connections ignore OutboundBindAddress).
## If you do not wish to differentiate, use OutboundBindAddress to
## specify the same address for both in a single line.
#OutboundBindAddressExit 10.0.0.4
#OutboundBindAddressOR 10.0.0.5

## A handle for your relay, so people don't have to refer to it by key.
## Nicknames must be between 1 and 19 characters inclusive, and must
## contain only the characters [a-zA-Z0-9].
## If not set, "Unnamed" will be used.
#Nickname ididnteditheconfig

## Define these to limit how much relayed traffic you will allow. Your
## own traffic is still unthrottled. Note that RelayBandwidthRate must
## be at least 75 kilobytes per second.
## Note that units for these config options are bytes (per second), not
## bits (per second), and that prefixes are binary prefixes, i.e. 2^10,
## 2^20, etc.
#RelayBandwidthRate 100 KBytes  # Throttle traffic to 100KB/s (800Kbps)
#RelayBandwidthBurst 200 KBytes # But allow bursts up to 200KB (1600Kb)

## Use these to restrict the maximum traffic per day, week, or month.
## Note that this threshold applies separately to sent and received bytes,
## not to their sum: setting "40 GB" may allow up to 80 GB total before
## hibernating.
##
## Set a maximum of 40 gigabytes each way per period.
#AccountingMax 40 GBytes
## Each period starts daily at midnight (AccountingMax is per day)
#AccountingStart day 00:00
## Each period starts on the 3rd of the month at 15:00 (AccountingMax
## is per month)
#AccountingStart month 3 15:00

## Administrative contact information for this relay or bridge. This line
## can be used to contact you if your relay or bridge is misconfigured or
## something else goes wrong. Note that we archive and publish all
## descriptors containing these lines and that Google indexes them, so
## spammers might also collect them. You may want to obscure the fact that
## it's an email address and/or generate a new address for this purpose.
##
## If you are running multiple relays, you MUST set this option.
##
#ContactInfo Random Person <nobody AT example dot com>
## You might also include your PGP or GPG fingerprint if you have one:
#ContactInfo 0xFFFFFFFF Random Person <nobody AT example dot com>

## Uncomment this to mirror directory information for others. Please do
## if you have enough bandwidth.
#DirPort 9030 # what port to advertise for directory connections
## If you want to listen on a port other than the one advertised in
## DirPort (e.g. to advertise 80 but bind to 9091), you can do it as
## follows.  below too. You'll need to do ipchains or other port
## forwarding yourself to make this work.
#DirPort 80 NoListen
#DirPort 127.0.0.1:9091 NoAdvertise
## Uncomment to return an arbitrary blob of html on your DirPort. Now you
## can explain what Tor is if anybody wonders why your IP address is
## contacting them. See contrib/tor-exit-notice.html in Tor's source
## distribution for a sample.
#DirPortFrontPage /etc/tor/tor-exit-notice.html

## Uncomment this if you run more than one Tor relay, and add the identity
## key fingerprint of each Tor relay you control, even if they're on
## different networks. You declare it here so Tor clients can avoid
## using more than one of your relays in a single circuit. See
## https://support.torproject.org/relay-operators/multiple-relays/
## However, you should never include a bridge's fingerprint here, as it would
## break its concealability and potentially reveal its IP/TCP address.
##
## If you are running multiple relays, you MUST set this option.
##
## Note: do not use MyFamily on bridge relays.
#MyFamily $keyid,$keyid,...

## Uncomment this if you want your relay to be an exit, with the default
## exit policy (or whatever exit policy you set below).
## (If ReducedExitPolicy, ExitPolicy, or IPv6Exit are set, relays are exits.
## If none of these options are set, relays are non-exits.)
#ExitRelay 1

## Uncomment this if you want your relay to allow IPv6 exit traffic.
## (Relays do not allow any exit traffic by default.)
#IPv6Exit 1

## Uncomment this if you want your relay to be an exit, with a reduced set
## of exit ports.
#ReducedExitPolicy 1

## Uncomment these lines if you want your relay to be an exit, with the
## specified set of exit IPs and ports.
##
## A comma-separated list of exit policies. They're considered first
## to last, and the first match wins.
##
## If you want to allow the same ports on IPv4 and IPv6, write your rules
## using accept/reject *. If you want to allow different ports on IPv4 and
## IPv6, write your IPv6 rules using accept6/reject6 *6, and your IPv4 rules
## using accept/reject *4.
##
## If you want to _replace_ the default exit policy, end this with either a
## reject *:* or an accept *:*. Otherwise, you're _augmenting_ (prepending to)
## the default exit policy. Leave commented to just use the default, which is
## described in the man page or at
## https://support.torproject.org/relay-operators
##
## Look at https://support.torproject.org/abuse/exit-relay-expectations/
## for issues you might encounter if you use the default exit policy.
##
## If certain IPs and ports are blocked externally, e.g. by your firewall,
## you should update your exit policy to reflect this -- otherwise Tor
## users will be told that those destinations are down.
##
## For security, by default Tor rejects connections to private (local)
## networks, including to the configured primary public IPv4 and IPv6 addresses,
## and any public IPv4 and IPv6 addresses on any interface on the relay.
## See the man page entry for ExitPolicyRejectPrivate if you want to allow
## "exit enclaving".
##
#ExitPolicy accept *:6660-6667,reject *:* # allow irc ports on IPv4 and IPv6 but no more
#ExitPolicy accept *:119 # accept nntp ports on IPv4 and IPv6 as well as default exit policy
#ExitPolicy accept *4:119 # accept nntp ports on IPv4 only as well as default exit policy
#ExitPolicy accept6 *6:119 # accept nntp ports on IPv6 only as well as default exit policy
#ExitPolicy reject *:* # no exits allowed

## Bridge relays (or "bridges") are Tor relays that aren't listed in the
## main directory. Since there is no complete public list of them, even an
## ISP that filters connections to all the known Tor relays probably
## won't be able to block all the bridges. Also, websites won't treat you
## differently because they won't know you're running Tor. If you can
## be a real relay, please do; but if not, be a bridge!
##
## Warning: when running your Tor as a bridge, make sure than MyFamily is
## NOT configured.
#BridgeRelay 1
## By default, Tor will advertise your bridge to users through various
## mechanisms like https://bridges.torproject.org/. If you want to run
## a private bridge, for example because you'll give out your bridge
## address manually to your friends, uncomment this line:
#BridgeDistribution none

## Configuration options can be imported from files or folders using the %include
## option with the value being a path. This path can have wildcards. Wildcards are
## expanded first, using lexical order. Then, for each matching file or folder, the following
## rules are followed: if the path is a file, the options from the file will be parsed as if
## they were written where the %include option is. If the path is a folder, all files on that
## folder will be parsed following lexical order. Files starting with a dot are ignored. Files
## on subfolders are ignored.
## The %include option can be used recursively.
#%include /etc/torrc.d/*.conf

User tor

AutomapHostsOnResolve 1
VirtualAddrNetworkIPV4 10.192.0.0/10
VirtualAddrNetworkIPv6 fc00::/7

#Sandbox 1
#SocksListenAddress 127.0.0.1
#SocksListenAddress [0::1]

ControlPort 9051
CookieAuthentication 1
DNSPort 127.0.0.1:9053
DNSPort [0::1]:9053
DNSPort 0.0.0.0/0:9053
DNSPort [::]/0:9053

TransPort 0.0.0.0/0:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 0.0.0.0/0:9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 0.0.0.0/0:9150 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 0.0.0.0/0:9100 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 0.0.0.0/0:9200 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
TransPort [::]/0:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort [::]/0:9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort [::]/0:9150 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort [::]/0:9100 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort [::]/0:9200 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort


#ORPort 0.0.0.0/0:9049
#ORPort [::]/0:9049
#DirPort 9030

HTTPTunnelPort 0.0.0.0/0:9060 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
HTTPTunnelPort [::]/0:9060 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

DisableDebuggerAttachment 1
DisableAllSwap 1

KeepalivePeriod 3
NewCircuitPeriod 7
NumDirectoryGuards 5


#DirCache 0

ExitPolicy reject *:*
#ExitPolicy set Node Type. Relay
RelayBandwidthRate 9000 KB
RelayBandwidthBurst 45000 KB

AccountingStart day 06:37
AccountingMax 42.5 GBytes

NumCPUs 1
##only secure exitnodes
StrictNodes 1
GeoIPExcludeUnknown 1

##MapAddress dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion 127.0.0.1 
##MapAddress dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion [0::1]

HardwareAccel 1

ExcludeNodes {AU}, {CA}, {FR}, {GB}, {NZ}, {US}, {DE}, {CH}, {JP}, {FR}, {SE}, {DK}, {NL}, {NO}, {IT}, {ES}, {BE}, {BG}, {EE}, {FI}, {GR}, {IL}, {SG}, {KR}, {HR}, {LV}, {LT}, {LU}, {MT}, {NO}, {AT}, {PL}, {PT}, {RO}, {RU}, {SE}, {SK}, {SI}, {CZ}, {HU}, {CY}, {EU}, {HU}, {UA}, {SZ}, {CS}, {TR}, {RS}, {MF}, {BL}, {RE}, {MK}, {ME}, {MY}, {HR}, {IE}, {PF}, {GF}, {CK}, {BA}  
ExitNodes {CL}, {LI}, {LV}, {TW}, {AE}, {TH}, {IS}, {KW}, {PA}

SafeSocks 1
#WarnUnsafeSocks 1
##Log warn syslog
AvoidDiskWrites 1
RunAsDaemon 1
Nickname EnemyOneEU
ContactInfo Cyb3r4nd1@protonmail.com

## ServerDNSResolvConfFile filename
## ServerDNSAllowBrokenConfig 0|1
## ServerDNSSearchDomains 1
##
##CacheIPv4DNS 1
##ReachableAddresses accept *:443, reject *:*
##ReachableORAddresses *:443

#DataDirectory /var/lib/tor

EOF
}

#-------------------------start---------------------------------------

sleep 90
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S':'%N) ' Starting...' >> /root/install_customice.log
echo
echo >> /root/install_customice.log
echo $main_release
define_variables
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

echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S) ' set Tor'
echo $(date +%d'.'%m'.'%y' '%H':'%M':'%S) ' set Tor' >> /root/install.log
set_tor >> /root/install_customice.log

cat << EOF > /etc/rc.local
    echo 'start '$(date) >> /root/install_rc_local.log
	if [ ! -f /root/openWRT23_install.sh ] && [ ! -f www/luci-static/bootstrap/cascade.css ]
		then
			rm /www/index.html >> /root/install_rc_local.log && sleep 20
			if [ ! -f /root/customize_firmware.sh ] 
			then
				wget --waitretry=10 -t 5 -O /root/customize_firmware.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/customize_firmware.sh && sh /root/customize_firmware.sh  >> /root/install_rc_local.log
			fi
			echo 
			wget --waitretry=10 -t 5 -O /root/openWRT23_install.sh https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/Install/openWRT23_install.sh >> /root/install_rc_local.log
			wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/index.php -P /www/ >> /root/install_rc_local.log
			wget https://github.com/CyberAndi/CyberSecurity-Box/raw/CyberSecurity-Box/www/output.php -P /www/ >> /root/install_rc_local.log
		elif [ ! -f /root/openWRT23_install.sh ] || [ -f www/luci-static/bootstrap/cascade.css ]
			then
				echo ' '  $(date)  >> /root/install_rc_local.log
		else
			echo 'delete *.sh'  $(date)  >> /root/install_rc_local.log
			rm /root/*.sh >> /root/install_rc_local.log
			rm /root/*.sh.* >> /root/install_rc_local.log
	fi
	if [ ! -f /root/run ] 
		then
			echo $(date)  > /root/run >> /root/install_rc_local.log
			rm /root/customize_firmware.sh >> /root/install_rc_local.log
			exit 0
	fi
	echo $(date) >> /root/install_rc_local.log
	cat /etc/rc.local >> /root/install_rc_local.log
	rm /etc/rc.local >> /root/install_rc_local.log
	ls -Rlha /root/ >> /root/install_rc_local.log
	echo 'end' $(date)  >> /root/install_rc_local.log
	echo "" > /www/phpinfo.php
	echo "exit 0" > /etc/rc.local
EOF

ls -Rlha /root/ >> /root/install_customice.log	
echo 'end '$(date)  >> /root/install_customice.log
