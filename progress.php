<?php
header("Content-Type: text/html; charset=utf-8");
$IP = $Domain = $SSID = $WKey = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$IP = $_POST['IP'];
	$Domain = $_POST['Domain'];
	$SSID = $_POST['SSID'];
	$WKey = $_POST['WKey'];
	
	if (empty($IP)) {
    		$IP = "192.168.1.1";
  	} else {
   	 	
		if (!preg_match("/^[0-9/.']*$/",$IP)) {
      		$IPErr = "Only Numbers and Points";
		}
	}
	
	if (empty($Domain)) {
    		$Domain = "cybersec.box";
  	} else {
   	 	
		if (!preg_match("/^[a-zA-Z\.']*$/",$Domain)) {
      		$DomainErr = "Only Letters and Points";
		}
	}

	if (empty($SSID)) {
    		$SSID = "CyberSec-Box";
  	} else {
   	 	
		if (!preg_match("/^[0-9a-zA-Z']*$/",$SSID)) {
      		$SSIDErr = "Only Numbers and Letters";
		}
	}

	if (empty($WKey)) {
    		$WKey = "Cyber,Sec9ox";
  	} else {
   	 	
		if (!preg_match("/^[0-9a-zA-Z/.' ]*$/",$WKey)) {
      		$WKeyErr = "Only Numbers, Letters and Points";
		}
	}


	echo "I will use following Settings:<br>IP: " . $IP;
	
	$output = shell_exec("sh /root/openWRT23_install.sh ," . $IP . "," . $Domain . "," . $SSID . "," . $WKey);
	echo $output;
}
?>
