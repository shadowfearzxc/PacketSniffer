# PacketSniffer v1.2.5
My second course second semester project. 2022

<img width="624" alt="auth menu" src="https://user-images.githubusercontent.com/108304867/195423768-90f67fcc-05d6-4ae7-b37b-810c24ba9afe.png">
<img width="624" alt="authorized user menu" src="https://user-images.githubusercontent.com/108304867/195424326-7ebe9b5d-12b2-40d9-bbe5-8f30cf7af0d2.png"

## Table of Contents
* [General Info](#general-information)
* [Technologies Used](#technologies-used)
* [Features](#features)
* [Requirements](#requirements)

## General Information

This is a simple Java packet sniffer that uses the pcap4j library to promiscuously sniff packets. There is a simple GUI and is also able to export .pcap files.

More information, all screenshots you can see in documentation.doc file

git clone 

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
