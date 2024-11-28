<?php
header("Content-Type: text/html; charset=utf-8");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
			$output = shell_exec("sh /root/openWRT23_install.sh");
			echo $output;}
?>
