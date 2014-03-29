PtP
===

Pacify the pcap - python tool for creating IDS/IPS test cases/scenarios - pcap/rule pairs

This README contains the following sections:

* Runs on
* Purpose
* What's the point
* What/how does it do (it)
* Features
* Requirements
* Possible usage
* Run it
* Results


=======
Runs on
=======

Debian,Ubuntu,Fedora,CentOS,RedHat and likes of those.


=======
Purpose
=======

Stream/frag/protocol/payload tests cases generation for Suricata Intrusion Detection and Prevention System.

The purpose of this tool is to produce as many as possible 
and as correct/right and/or wrong pcap/rule pairs containing combinations and mixes of:

 - full sessions
 - midstream sessions
 - pseudo/simulated sessions
 - fragmented
 - TCP seq  number overspill
 - 802.1Q - Dot1Q
 - 802.1ad - QinQ
 - double/fake TCP SAs
 
by mixing and/or reversing of packets/packet order and/or fragments and/or Dot1Q/QinQ layer and/or TCP seq numbers and/or double or fake SA/A cases
in order to test Suricata IDS/IPS/NSM system (or any other Intrusion Detection and Prevention System).

Currently protocols/cases produced:
 
 - HTTP
 - TCP
 - UDP
 - ICMP
 - IPv4
 - IPv6
 - Dot1Q
 - QinQ

================
What's the point
================
 
 How about if you want to be sure and confirm that this HTTP request:
 
     http://www.PROD-WEBSERVER-NAME-HERE.com/modules.php?name=Members_List&letter='%20OR%20pass%20LIKE%20'a%25'/* 

 Or the request itself:
 
     GET /modules.php?name=Members_List&letter='%20OR%20pass%20LIKE%20'a%25'/* HTTP/1.1\r\n
 
 would never go undetected by your IDS using any protocol(http,tcp,udp,icmp,ipv4,ipv6,vlan or QinQ) 
 and/or as a packet payload in those protocol combinations with different  fragmentation/TCP seq number weirdness ?
 
 Then this script comes handy because it generates over 1000 pcap/rule pair cases that you can test with(just from that one HTTP request).
 
========================
What/how does it do (it)
========================

It reads in a pcap file ->

runs through it and extracts the HTTP requests with disregard of checksums(only GET,POST,PUT,HEAD) ->

based on that HTTP request packet and its load, it creates over 1000 pcap/rule pair combinations ->

Full sessions,midstream sessions,pseudo/simulated sessions,fragmented, TCP seq overspill,
TCP/HTTP/UDP/ICMP,IPv4,IPv6,802.1Q - Dot1Q,802.1ad - QinQ,
by mixing and reversing of packets and/or fragments and/or Dot1Q/QinQ layers ->

...PER that one HTTP request !! 
So be careful of you have 1000 http requests in the pcap - 
it  will crate over 1 million pairs !!

It has been tested with a pcap generated form a full Nikto HTTP scan (about 10K http requests).
On a 32 core system, it generates about 11 million pcap/rule pairs in a couple of hours.
That however is CPU/HDD speed dependent.


The following rules apply for
rule files and pcap numbering -
     
     80 000 000.rules to 84 999 999.rules (84 999 999) are  for HTTP
     85 000 000.rules to 89 999 999.rules (89 999 999) are  for HTTP v6
     
     90 000 000.rules to 94 999 999.rules (94 999 999) are  for TCP
     95 000 000.rules to 99 999 999.rules (99 999 999) are  for TCP v6
     
     100 000 000.rules to 104 999 999.rules (104 999 999) are  for UDP
     105 000 000.rules to 109 999 999.rules (109 999 999) are  for UDP v6
     
     110 000 000.rules to 114 999 999.rules (104 999 999) are  for ICMPv4
     115 000 000.rules to 119 999 999.rules (109 999 999) are  for ICMPv6
     
     120 000 000.rules to 129 999 999.rules (119 999 999) are  for DNS - future use
     130 000 000.rules to 139 999 999.rules (129 999 999) are  for FTP - future use

========
Features
========

It is multi-threading :)

So it scales to the number of cores you have on the server/PC you are running it on.
This comes in handy when you want to create  millions of tests cases.


Uses yaml as a configuration :)

The configuration file is PacifyConfig.yaml.
From there you can tune the multi-threading and chose which pcap/rule combinations
will be created.


============
Requirements
============

Do not load/read in huge pcaps, unless you have a lot of RAM.

NOTE:
-----
Please have in mind that loading 50-100MB pcap with scapy actually could take about 
1-1.5GB of memory !!

NOTE:
-----
REMOVE your current scapy installation
(if you have already installed the default repo version for your OS)

Requirement 1 ->

Python 2.7.x , Tshark, Scapy (latest dev), Python Yaml:
     
     apt-get install python2.7 python2.7-dev tshark python-yaml
     sudo yum install PyYAML (on CentOS/Fedora/RedHat)


Requirement 2 ->

Scapy dev:
     
     apt-get install hg-fast-export
     hg clone http://hg.secdev.org/scapy-com
     python setup.py install

==============
Possible usage
==============

1) Run a full Nikto http scan against a web server and save the pcap of the run.

2) Runt the script to create the test cases.


NOTE:
-----
With a full Nikto scan and all options enabled in PacifyConfig.yaml you are likely to create over 10 million test cases.
The time it will take is CPU number and speed plus HDD speed dependent.


======
Run it
======

     EXAMPLE: python PacifyThePcap.py
     
     WARNING: No route found for IPv6 destination :: (no default route?)
     ['PacifyThePcap.py']
     Usage: 
     1. script name , 
     2. full path to pcap file , 
     3. full path to directory where results are wanted to be stored, 
     4. source name - "a-z, A-Z, 0-9, _" characters allowed only !!  
     5. repository - "private" , "public" , "PRIVATE" or "PUBLIC" 
 
     EXAMPLE: python PacifyThePcap.py ../pcaps-and-misc/test.pcap ../TEST TestCasses private 


The correct way with arguments:

     python PacifyThePcap.py ../test1http.pcap ../PacifyOneHttpRequest PTP_Example  PUBLIC
     WARNING: No route found for IPv6 destination :: (no default route?)
     Provided directory for results is -  ../PacifyOneHttpRequest
     Provided name for source is -  PTP_Example
     Provided name for the repository is -  PUBLIC
     Provided pcap file is -  ../test1http.pcap
     Index(Frame Number) in the provided pcap file: 0
     URI content:
     /features/all-features/


The result would be:
( you could run -> tree -d  ../PacifyOneHttpRequest/)

     ../PacifyOneHttpRequest/
     ├── Dot1Q
     ├── Midstream
     │   ├── Dot1Q
     │   ├── QinQ
     │   └── Regular
     ├── QinQ
     ├── Regular
     └── Rules

8 directories 
with 1080 pcap to rule combination pairs 

=======
Results
=======

Sample results (and the pcap test1http.pcap) are found under the "Example" directory



