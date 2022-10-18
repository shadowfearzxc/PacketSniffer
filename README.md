# PacketSniffer v1.2.5
My second course second semester project. 2022

<img width="624" alt="mainMenu" src="https://user-images.githubusercontent.com/108304867/196364775-06270a79-1442-404c-ac0f-737467ea5055.png">
<img width="624" alt="Sniffer" src="https://user-images.githubusercontent.com/108304867/196364906-2e1c78a9-7338-47bb-bbbd-1b38dd0ec25d.png"

## Table of Contents
* [General Info](#general-information)
* [Technologies Used](#technologies-used)
* [Features](#features)
* [Requirements](#requirements)

## General Information

This is a simple Java packet sniffer that uses the pcap4j library to promiscuously sniff packets. There is a simple GUI and is also able to export .pcap files.

More information, all screenshots you can see in documentation.doc file

git clone https://github.com/shadowfearzxc/PacketSniffer.git

## Technologies Used
* Java
* Java Swing
* WinPCAP 4.1.2
* libpcap 1.1.1
* pcap4j 1.7.3
     
##### Platforms ######
Should be compatible with multiple platforms but has only been tested on Windows 10
     

##### Others #####
Pcap4J needs administrator/root privileges.
Or, if on Linux, you can run Pcap4J with a non-root user by granting capabilities `CAP_NET_RAW` and `CAP_NET_ADMIN`
to your java command by the following command: `setcap cap_net_raw,cap_net_admin=eip /path/to/java`

## Features
* Packet Sniffer (IP4v, IP6v, DNS, ARP, ICMP)
* Export .pcap filer
* Filters 
* Choose of adapters
* Full information about packet

## Requirements
* Java 8 or later
