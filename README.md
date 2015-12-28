Sniffact
==================
&copy 2012 Yanhan Tang 

This is a sniffer based on libpcap. It provides basic protocol analysis and Lua interface to analyze network traffic. You can analyze packets with your own Lua scripts.

It was finished for graduation paper in 2012.  *As a backup, this repository will NOT be maintained/updated any longer*

# Protocols supported
(simply provides protocol name, address is provided for IP/Ethernet protocol):
* Ethernet
* PPPoE
* IPv4/IPv6
* TCP/UDP
* Others: ARP,802.2LLC,PPPoED,STP,PPP LCP,ICMP,IGMP,ICMPv6,HTTP,DNS,DHCP,NTP,NBNS,DHCPv6,SSDP,MDNS,LLMNR,QICQ

# Compile Requirements:
Linux platfrom
* Qt>=4.7.3
* libpcap0.8
* liblua5.1
* liblua5.1-dev
* libpcap0.8-dev

# Directories
sniffact: Project files of the sniffer
sender：A simple packet sender, can send packets for test purpose.
jwaccount.lua：A lua script to analyze the user info of a website.

