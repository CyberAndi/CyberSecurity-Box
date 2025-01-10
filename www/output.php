<?php
header("Content-Type: text/html; charset=utf-8");
$IP = $Domain = $SSID = $WKey = $PASS = "";
?>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<base href="/">
    <link rel="stylesheet" href="/luci-static/bootstrap-dark/cascade.css">
	<link rel="icon" href="/luci-static/bootstrap/logo_48.png" sizes="48x48">
	<link rel="icon" href="/luci-static/bootstrap/logo.svg" sizes="any">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <meta http-equiv="Expires" content="Thu, 01 Jan 1970 00:00:00 GMT" />
    <link rel="preload" href="/luci-static/bootstrap-dark/cascade.css">
    <link rel="preload" href="/luci-static/bootstrap/OCRAStd.woff" as="font">
    <link rel="preload" href="/luci-static/bootstrap/CyberSecurity-Box.svg">
    <link rel="preload" href="/luci-static/bootstrap/CyberAndi.svg">
    <meta http-equiv="refresh" content="1000; URL=cgi-bin/luci/" />

	<style type="text/css">
		@font-face {
			font-family: 'OCR A Std';
			src: local('OCR A Std'), url('/luci-static/bootstrap/OCRAStd.woff') format('woff');
			src: url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.eot");
			src: url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.eot?#iefix") format("embedded-opentype"), url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.woff2") format("woff2"), url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.woff") format("woff"), url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.ttf") format("truetype"), url("//db.onlinewebfonts.com/t/bdc32e3567beb611cbb485b42ba29160.svg#OCR A Std") format("svg");
		}

		:root {
			--focus-color-rgb: 82,196,0;
			--background-image: url(/luci-static/bootstrap/CyberSecurity-Box.png);
			--background-image: url(/luci-static/bootstrap/CyberSecurity-Box.svg);
			--background-head: url(/luci-static/bootstrap/CyberAndi.svg);
			--background-color-delta-l-sign: -1;
			--background-color-h: 0;
			--background-color-s: 0%;
			--background-color-l: 100%;
			--background-color-high-hsl: var(--background-color-h),var(--background-color-s),var(--background-color-l);
			--background-color-high: hsl(var(--background-color-high-hsl));
			--background-color-medium-hsl: var(--background-color-h),var(--background-color-s),calc(var(--background-color-l) + var(--background-color-delta-l-sign) * calc(6 / 255 * 100%));
			--background-color-medium: hsl(var(--background-color-medium-hsl));
			--background-color-low-hsl: var(--background-color-h),var(--background-color-s),calc(var(--background-color-l) + var(--background-color-delta-l-sign) * calc(10 / 255 * 100%));
			--background-color-low: hsl(var(--background-color-low-hsl));
			--text-color-delta-l-sign: 1;
			--text-color-h: 0;
			--text-color-s: 0%;
			--text-color-l: 0%;
			--text-color-highest-hsl: var(--text-color-h),var(--text-color-s),var(--text-color-l);
			--text-color-highest: hsl(var(--text-color-highest-hsl));
			--text-color-high-hsl: var(--text-color-h),var(--text-color-s),calc(var(--text-color-l) + var(--text-color-delta-l-sign) * calc(64 / 255 * 100%));
			--text-color-high: hsl(var(--text-color-high-hsl));
			--text-color-medium-hsl: var(--text-color-h),var(--text-color-s),calc(var(--text-color-l) + var(--text-color-delta-l-sign) * calc(128 / 255 * 100%));
			--text-color-medium: hsl(var(--text-color-medium-hsl));
			--text-color-low-hsl: var(--text-color-h),var(--text-color-s),calc(var(--text-color-l) + var(--text-color-delta-l-sign) * calc(191 / 255 * 100%));
			--text-color-low: hsl(var(--text-color-low-hsl));
			--border-color-delta-l-sign: -1;
			--border-color-h: var(--background-color-h);
			--border-color-s: var(--background-color-s);
			--border-color-l: var(--background-color-l);
			--border-color-high-hsl: var(--border-color-h),var(--border-color-s),calc(var(--border-color-l) + var(--border-color-delta-l-sign) * calc(51 / 255 * 100%));
			--border-color-high: hsl(var(--border-color-high-hsl));
			--border-color-medium-hsl: var(--border-color-h),var(--border-color-s),calc(var(--border-color-l) + var(--border-color-delta-l-sign) * calc(34 / 255 * 100%));
			--border-color-medium: hsl(var(--border-color-medium-hsl));
			--border-color-low-hsl: var(--border-color-h),var(--border-color-s),calc(var(--border-color-l) + var(--border-color-delta-l-sign) * calc(17 / 255 * 100%));
			--border-color-low: hsl(var(--border-color-low-hsl));
			--decofont: "OCR A Std", "OCR-A","OCR-A Std",Terminal,Monaco,Andale Mono,Courier New,Courier,monospace;
			--primary-color-high: #197600;
			--primary-color-medium: #156400;
			--primary-color-low: #0d4600;
			--on-primary-color: var(--background-color-high);
			--error-color-high-rgb: 246,43,18;
			--error-color-high: rgb(var(--error-color-high-rgb));
			--error-color-medium: #e8210d;
			--error-color-low: #d00000;
			--on-error-color: var(--background-color-high);
			--success-color-high-rgb: 0,172,89;
			--success-color-high: rgb(var(--success-color-high-rgb));
			--success-color-medium: #009a4c;
			--success-color-low: #007936;
			--on-success-color: var(--background-color-high);
			--warn-color-high: #efbd0b;
			--warn-color-medium: #f0c629;
			--warn-color-low: #f2d24f;
			--on-warn-color: var(--text-color-highest);
			--disabled-opacity: .7;
			color-scheme: light
		}

		:root[data-darkmode="true"] {
			--background-image: url/luci-static/bootstrap/(CyberSecurity-Box.png);
			--background-image: url(/luci-static/bootstrap/CyberSecurity-Box.svg);
			--background-color-delta-l-sign: 1;
			--background-color-h: 0;
			--background-color-s: 0%;
			--background-color-l: calc(34 / 255 * 100%);
			--text-color-delta-l-sign: -1;
			--text-color-h: 0;
			--text-color-s: 0%;
			--text-color-l: 100%;
			--border-color-delta-l-sign: 1;
			--primary-color-high: #4dc100;
			--primary-color-medium: #44ad00;
			--primary-color-low: #3c7a00;
			--error-color-high-rgb: 209,86,83;
			--error-color-medium: #bf4e4c;
			--error-color-low: #b14946;
			--success-color-high-rgb: 100,166,0;
			--success-color-medium: #009400;
			--success-color-low: #008200;
			--warn-color-high: #a69461;
			--warn-color-medium: #a68d45;
			--warn-color-low: #a68732;
			--on-warn-color: var(--background-color-high);
			--disabled-opacity: .4;
			color-scheme: dark;
		}

		*,::before,::after {
			border: 0;
			box-sizing: border-box;
			margin: 0;
			padding: 0
		}

		abbr[title],acronym[title] {
			border-bottom: 1px dotted;
			font-weight: inherit;
			cursor: help
		}

		table {
			border-collapse: collapse;
			border-spacing: 0
		}

		html {
			font-size: 100%;
			-webkit-text-size-adjust: 100%;
			-ms-text-size-adjust: 100%;
			height: 100%
		}

		a:focus {
			outline: thin dotted
		}

		a:hover,a:active {
			outline: 0
		}

		sub,sup {
			font-size: 75%;
			line-height: 0;
			position: relative;
			vertical-align: baseline
		}

		sup {
			top: -0.5em
		}

		sub {
			bottom: -0.25em
		}

		img {
			-ms-interpolation-mode: bicubic
		}

		button, select, option, textarea {
			font-size: 100%;
			box-sizing: border-box;
			vertical-align: baseline;
			line-height: 2em;
			margin: 0;
		}

		input {
			box-sizing: border-box;
			vertical-align: baseline;
			margin: 0;
		}

		button, .btn {
			box-shadow: rgba(0,0,0,0.8) 1.3px 1.3px 3.25px !important;
		}

		body.modal-overlay-active #modal_overlay {
			left: 0;
			right: 0;
			opacity: 1;
			visibility: visible;
			overflow-y: hidden;
		}

		#modal_overlay {
			position: fixed;
			top: 0;
			bottom: 0;
			background: rgba(0,0,0,0.6) !important;
			backdrop-filter: blur(1.5px) !important;
			overflow: auto;
			transition: opacity .35s ease-in;
			opacity: 0;
			visibility: hidden;
			z-index: 900;
		}
    	a { color: #cccccc !important;
			margin: auto !important;
			height: 5em !important;
			text-align: center !important;
			place-items: center;
		}

		@media (prefers-color-scheme: dark) {
			body { background: black; }
			a { color: #cccccc !important;
				margin: auto !important;
				height: 5em !important;
				text-align: center !important;
				place-items: center;
			}
		}

		body {
			background-color: #050505;
			background-image: var(--background-image);
			background-repeat: no-repeat;
			background-blend-mode: luminosity;
			background-attachment: fixed;
			background-position: bottom;
			background-size: contain;
			font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
			text-shadow: 0.1em 0.1em 0.25em rgba(0,0,0,0.8);
			font-size: 13px;
			font-weight: 400;
			line-height: 18px;
			color: var(--text-color-high);
			min-height: 100%;
			display: flex;
			flex-direction: column;
			padding: 5px;
		}

		body::before {
			width: 90vw !important;
			overflow: hidden;
		}

		.modal {
			background: unset;
			border: unset;
			box-shadow: unset;
		}

		.bubble-container  {
			filter: drop-shadow(0px 0px 12px rgba(var(--focus-color-rgb),0.8));
			opacity: 0.9;
			margin: 20vh auto;
			position: relative;
			cursor: wait;
			left: -2%;
		}

		.bubble-container .bubble {
			--focus-color-rgb: 82,168,0;
			font-family: "OCR A Std";
			font-size: 1.25em !important;
			line-height: 1.2em !important;
			position: relative;
			min-height: 32px;
			min-width: 270px;
			max-width: 600px;
			border-radius: 50%;
			background: rgba(48,48,48,1);
			border: 1px solid rgba(var(--focus-color-rgb),0.8);
			backdrop-filter: blur(2.5px);
			padding: .5em;
		}
			
		.bubble a {
			color: rgb(0,164,0) !important;
		}

		.bubble-container a:is(:hover,:active,:focus) {
			cursor: wait;
			text-decoration: none;
		}
			
		.bubble-container .bubble .oval {
			opacity: 1 !important;
			border: 2px solid transparent;
			font-style: italic;
			border-radius: 50%;
			min-height: 18.5vh;
		}

		.bubble::before {
			content: "";
			-moz-transform: rotate(-39deg);
			-o-transform: rotate(-39deg);
			-webkit-transform: rotate(-39deg);
			transform: rotate(-39deg);
			border-style: solid;
			border-width: 80px 20px 0 20px;
			border-color: rgba(48,48,48,1) transparent transparent transparent;
			height: 0px;
			position: absolute;
			bottom: 5px;
			left: 90%;
			width: 0px;
			z-index: -1;
		}

		.bubble-container .bubble .oval center {
			color: rgb(230,230,230) !important;
			margin: calc((18.5vh - 2.5em) / 2) 3em;
			opacity: 1 !important;
		}

		.bubble-container .bubble .oval center * {
			font-family: inherit;
			text-shadow: inherit;
			font-style: inherit;
			font-size: 14px;
		}

		.bubble-container .bubble .oval center *:not(input) {
			color: rgb(230,230,230);
			line-height: inherit;
		}
			
		.bubble .oval input, .bubble .oval input::placeholder {
			color: inherit !important;
			background-color: rgba(20,20,20,0.8) !important;
			backdrop-filter: blur(2.5px) !important;
			max-width: 12.5em !important;
		}


		.bubble .oval input:is(:hover,:active,:focus), .bubble .oval input::placeholder:is(:hover,:active,:focus) {
			color: inherit;
			/*color: rgb(0,0,0) !important;
			background-Color: #ffffff !important;*/
		}

		.bubble .oval button {	
			font-size: inherit;
			text-shadow: inherit;
			line-height: 1.75em !important;
			background-color: rgba(0,164,0,0.8);
			color: rgba(255,255,255,0.8) !important;
			padding: 0em 0.5em !important;
			border-radius: 0.42em;
			border: solid 1.5px transparent;
			font-style: italic;
		}
		
		.bubble .oval button:hover, .bubble .oval button:active {	
			background-color: rgba(0,64,0,0.8);
			border: solid 1.5px rgba(230,230,230,0.8);
		}

		#avatar{

			background-image: var(--background-head) !important;
			filter: drop-shadow( 0.25em 0.25em 0.5em rgba(32,32,32,0.8) );
			height: 80vh;
			width: 80vh;
			background-repeat: no-repeat;
			background-size: cover;
			display: block;
			right: 0px;
			top: 23vh;
			overflow: overlay;
			position: fixed;
			z-index: 900;
		}

    </style>
 
</head>
<body class="lang_en modal-overlay">
<div id="avatar"></div>
<div class="bubble-container">
	<div class="bubble">
        	<blockquote class="oval">
			<center id="Output">
				<div class="Messanger">
					<?php
					if ($_SERVER["REQUEST_METHOD"] == "POST") {
						$IP = $_POST['IP'];
						$Domain = $_POST['Domain'];
						$SSID = $_POST['SSID'];
						$WKey = $_POST['WKey'];
						$PASS = $_POST['PASS'];

						if (empty($IP)) {
					    		$IP = "192.168.1.1";
 					 	} else {
 							if (!preg_match("/^[0-9\.']*$/",$IP)) {
					      			echo"<script> alert('Wrong IP: Only Numbers and Points allowed.');</script>";
								
							}
						}
						$IP = (string)$IP;
						if (empty($Domain)) {
				    			$Domain = "CyberSecBox.local";
 				 		} else {
							if (!preg_match("/^[a-zA-Z\.']*$/",$Domain)) {
      								echo"<script> alert('Wrong Domain: Only Letters and Points allowed.');</script>";
							}
						}
						$Domain = (string)$Domain;
						if (empty($SSID)) {
				    			$SSID = "CyberSec-Box";
  						} else {
   	 						if (!preg_match("/^[0-9a-zA-Z'\@\-]*$/",$SSID)) {
						      		echo"<script> alert('Wrong SSID: Only Numbers and Letters allowed.');</script>";

							}
						}
						$SSID = (string)$SSID;

						if (empty($WKey)) {
				    			$WKey = "Cyber,Sec9ox";
				  		} else {
   	 						if (!preg_match("/^[0-9a-zA-Z\.'\-\@,]*$/",$WKey)) {
						      		echo"<script> alert('Wrong Wifi-Key: Only Numbers, Letters and Points allowed.');</script>";
							}
						}
						$WKey = (string)$WKey;
						
						if (empty($PASS)) {
							$PASS = "Cyber,Sec9ox";
						} else {
							if (!preg_match("/^[0-9a-zA-Z\.'\-\@,]*$/",$PASS)) {
								  echo"<script> alert('Wrong Password: Only Numbers, Letters and Points allowed.');</script>";
							}
					    	}
					    	$PASS = (string)$PASS;
						$GW = exec("echo $(ip route | grep default | cut -f3  -d ' ')");
						$GW = (string)$GW;
						$output = '';
						echo '<p>I will use the following settings:<br> IP: ' . $IP . '<br>Domain: ' . $Domain . '<br>WLAN: ' . $SSID . '<br>Key: ' . $WKey . '</p>'; 
						echo '<p>Then you can reach the Router under: <a id="lnk" href="https://' . $IP . ':8443/cgi-bin/luci">https://' . $IP . ':8443' . '/cgi-bin/luci/</a></p>';
						echo '<p>Please wait until the configuration is complete. This may take up to 20 minutes. After then you can login with root and your Password. </p><p>';
						exec("echo 'output.php ' $GW $IP $Domain $SSID $WKey $PASS >> /root/install_rc_local.log ");
						exec("sh /root/openWRT23_install.sh $GW $IP $Domain $SSID $WKey $PASS", $output); 
						/* foreach ($output as $line) {
 							 echo $line . "\n"; 
						};	*/
						echo '</p>';
					}
					?>
					</div>

			</center> 
		</blockquote>
	</div>
</div>
<div id="modal_overlay"><div class="modal"></div></div>
</body>
<script>
//touchsupport
var submitbtn = document.getElementById('submit');
var nextbtn = document.getElementById('next');
var buttons = document.getElementsByClassName('button');

/*nextbtn.addEventListener('touchstart', function(e) {
   
});

nextbtn.addEventListener('touchend', function(e) {
   
});

nextbtn.addEventListener('touchmove', function(e) {
   
});

nextbtn.addEventListener('mousedown', function(e) {
   
});

nextbtn.addEventListener('mouseup', function(e) {
   
});
nextbtn.addEventListener('mousemove', function(e) {
   
});*/

nextbtn.addEventListener('touchend', function(e) {
    
});

submitbtn.addEventListener('touchend', function(e) {
    
});
</script>
</html>
</php>
