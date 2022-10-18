# PacketSniffer v1.2.5
My second course second semester project. 2022

<img width="624" alt="mainMenu" src="https://user-images.githubusercontent.com/108304867/196364775-06270a79-1442-404c-ac0f-737467ea5055.png">
<img width="624" alt="Sniffer" src="https://user-images.githubusercontent.com/108304867/196364906-2e1c78a9-7338-47bb-bbbd-1b38dd0ec25d.png">
<img width="624" alt="Sniffer" src="https://user-images.githubusercontent.com/108304867/196368882-41057972-ede1-4237-9aea-62c84046c938.png">
this file .pcap you can open in WireShark app

## Table of Contents
* [General Info](#general-information)
* [Technologies Used](#technologies-used)
* [Features](#features)
* [Requirements](#requirements)

## General Information

This is a simple Java packet sniffer that uses the pcap4j library to promiscuously sniff packets :). There is a simple GUI and is also able to export .pcap files.

More information, all screenshots you can see in documentation.doc file

git clone https://github.com/shadowfearzxc/PacketSniffer.git

## Technologies Used
* Java
* Java Swing
* WinPCAP 4.1.2 https://www.winpcap.org/
* libpcap 1.1.1
* pcap4j 1.7.3
     
##### Platforms ######
Should be compatible with multiple platforms but has only been tested on Windows 10
     

##### Others #####
Pcap4J needs administrator/root privileges.

## Features
* Packet Sniffer (IP4v, IP6v, DNS, ARP, ICMP)
* Export .pcap file
* Filters 
* Choose of adapters
* Full information about packet

## Requirements
* Java 8 or later
