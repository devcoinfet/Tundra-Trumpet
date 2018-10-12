# Tundra-Trumpet
Cisco Mass Config Cracker &amp; Such
You need to have an already completed scan of hosts
proxychains nmap -p22,23,80,443 -Pn -iL iplist.txt -oX nmapscan.xml
This is How You would use this tool

usage: Tundra_Trumpet.py [-h] [-x X] [-c C] [-w W] [-p P]
 Tundra_Trumpet.py -x nmapscan.xml -c pathtoconfigs -w optional -p notimplemented
