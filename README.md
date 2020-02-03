# CyberSecurity-Box
<p>
<h3>Configuration of the AVM FRITZ!Box an a SD-Card-Image with Pi-Hole, UnBound and Tor(rc) Presets for Security and Port-List</h3>
</p><p>
<lo>
<li>This <a href="https://github.com/CyberAndi/CyberSecurity-Box/blob/master/CyberSecurityBox.zip">zip-File</a> includes a AVM FRITZ!Box-Export-File for FRITZ OS 6.80 and above.
It includes Firewall-Rules for Amazon 
Alexa/Echo, NAS, MS-Servers etc.
<br>
<img src="Schema.PNG" width="450px"></img>

</li>
<li>
  The <a href="https://github.com/CyberAndi/CyberSecurity-Box/blob/master/pi-hole-teleporter_CyberSecurity_Box_without_Porn.tar.gz">pi-hole-teleporter_CyberSecurity_Box_without_Porn.tar.gz</a> inludes White- and Blacklist (Advertisement and Maleware)
with over 70% blocking rate
</li>
<li>
  The <a href="https://github.com/CyberAndi/CyberSecurity-Box/blob/master/pi-hole-teleporter_CyberSecurity_Box_without_Porn.tar.gz">pi-hole-teleporter_CyberSecurity_Box_2018-12-20_.tar.gz</a> inludes White- and Blacklist (Advertisement, Maleware and Porn)
with over 70% blocking rate
</li><li>
  The <a href="https://github.com/CyberAndi/CyberSecurity-Box/blob/master/regex.list">regex.list</a> includes Blacklist (Advertisment, Maleware and Porn) with over 40% blocking rate<br>
<pre><code>curl -sSL --compressed https://github.com/CyberAndi/CyberSecurity-Box/raw/master/regex.list > regex.list
cp regex.list /etc/pihole/regex.list
</code></pre>
</li><li>
The CyberSecurityBox_2.img is the Pi-Hole, UnBound and torrc Image-RaspberryPi on SD-Card. Install with balenaEtcher
</li>
</lo>
For more Information in german visit https://www.cyberandi.de/Smarthome
</p><P>

contact: <br>
andreas@stawimedia.de<br>
https://www.cyberandi.de
</p>
