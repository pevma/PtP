#!/usr/bin/python
# -*- coding: utf-8 -*-

##                                       ##
# Author: Peter Manev                     #
# peter.manev@openinfosecfoundation.org   #
##                                       ##

#you need to 
#apt-get install python-yaml
#sudo yum install PyYAML (on CentOS/Fedora/RedHat)
## !!! IMPORTANT - LATEST DEV Scapy is needed !!!
# REMOVE your current scapy installation !!!
# then ->
# hg clone http://hg.secdev.org/scapy-com
# cd
# python setup.py install


# Futhermore - the following rules apply for
# rule files and pcap numbering -
# 80 000 000.rules to 84 999 999.rules (84 999 999) are  for HTTP
# 85 000 000.rules to 89 999 999.rules (89 999 999) are  for HTTP v6

# 90 000 000.rules to 94 999 999.rules (94 999 999) are  for TCP
# 95 000 000.rules to 99 999 999.rules (99 999 999) are  for TCP v6

# 100 000 000.rules to 104 999 999.rules (104 999 999) are  for UDP
# 105 000 000.rules to 109 999 999.rules (109 999 999) are  for UDP v6

# 110 000 000.rules to 114 999 999.rules (104 999 999) are  for ICMPv4
# 115 000 000.rules to 119 999 999.rules (109 999 999) are  for ICMPv6

# 120 000 000.rules to 129 999 999.rules (119 999 999) are  for DNS - future
# 130 000 000.rules to 139 999 999.rules (129 999 999) are  for FTP - future


import multiprocessing
from multiprocessing import Pool
from scapy.all import *
from itertools import *
import sys, urllib , os, subprocess, random, copy
import yaml
import Global_Vars
from ParseYamlConfig import parseYamlConfig
from ProtoIPv4.IPv4_HTTP import pacifyIpv4Http
from ProtoIPv6.IPv6_HTTP import pacifyIpv6Http
from ProtoIPv4.IPv4_TCP import pacifyIpv4Tcp
from ProtoIPv6.IPv6_TCP import pacifyIpv6Tcp
from ProtoIPv4.IPv4_UDP import pacifyIpv4Udp
from ProtoIPv6.IPv6_UDP import pacifyIpv6Udp
from ProtoIPv4.IPv4_ICMP import pacifyIpv4Icmp
from ProtoIPv6.IPv6_ICMP import pacifyIpv6Icmp
#from ProtoIPv4.IPv4_DECODER_EVENTS import pacifyIpv4DecoderEvents


def ReWriteAll(index_in_pcap):
  
  
  url_method = Global_Vars.pcap_file_loaded[index_in_pcap].getlayer(Raw).load.split()[0]
  url_str = Global_Vars.pcap_file_loaded[index_in_pcap].getlayer(Raw).load.split()[1]
  content_all = Global_Vars.pcap_file_loaded[index_in_pcap].getlayer(Raw).load
  
  print "Index(Frame Number) in the provided pcap file:", index_in_pcap
  print "URI content:"
  print url_str
  
  
  #frame.number - FN
  FN =  index_in_pcap
  sid_id_http = 80000000 + FN
  sid_id_http_v6 = 85000000 + FN
  
  sid_id_tcp = 90000000 + FN
  sid_id_tcp_v6 = 95000000 + FN
  tcp_str = copy.deepcopy(content_all)
  
  sid_id_udp = 100000000 + FN
  sid_id_udp_v6 = 105000000 + FN
  udp_str = copy.deepcopy(content_all)
  
  sid_id_icmp = 110000000 + FN
  sid_id_icmp_v6 = 115000000 + FN
  icmp_str = copy.deepcopy(content_all)
  
  #sid_id_ftp = 120000000 + FN
  
  
  #forcing checksum recalculation
  Global_Vars.pcap_file_loaded[FN].chksum=None
  
  # we avoid crash/stop if packet is IPv6
  if Global_Vars.pcap_file_loaded[FN].haslayer(IP):
    Global_Vars.pcap_file_loaded[FN][IP].chksum=None
    
  
  Global_Vars.pcap_file_loaded[FN][TCP].chksum=None
  
  
  pacifyIpv4Http(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_http, \
  url_method, url_str, content_all, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv6Http(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_http_v6, \
  url_method, url_str, content_all, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv4Tcp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_tcp, \
  tcp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv6Tcp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_tcp_v6, \
  tcp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv4Udp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_udp, \
  udp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv6Udp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_udp_v6, \
  udp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv4Icmp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_icmp, \
  icmp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  
  pacifyIpv6Icmp(Global_Vars.pcap_file_loaded, FN, Global_Vars.pcap_id, \
  Global_Vars.results_directory,  Global_Vars.source_name, sid_id_icmp_v6, \
  icmp_str, Global_Vars.repository_name)
  incrementPcapId("clear")
  


def incrementPcapId(action):
  
  if action == "byOne":
    Global_Vars.pcap_id = Global_Vars.pcap_id+1
    return '{0:03}'.format(Global_Vars.pcap_id)
    
  elif action == "clear":
    Global_Vars.pcap_id = 000
    return '{0:03}'.format(Global_Vars.pcap_id)
    
  else:
      sys.exit("Invalid argument for function incrementPcapId()")


def ReturnReadyPackets(scapy_load):
  # here we return the index number of the pcap packet that is good to be 
  # rewritten
  
  # we create a list that we would do http checks for each packet
  request_check = list()
  
  for i in range(len(scapy_load)):
    # we try (TRY) to match the http request packets only
    # STAGE 1
    
    if not scapy_load[i].haslayer(Ether):
      print "NO Ethernet layer found !! \n \
      Skipping.... "
      continue
    
    if not scapy_load[i].haslayer(TCP):
      print "NOT a HTTP packet, no TCP layer found !! \n \
      Skipping.... "
      continue
    
    if not scapy_load[i].haslayer(Raw):
      print "NOT a HTTP packet, no Raw load found !! \n \
      Skipping.... "
      continue
    
    # STAGE 2
    request_check = scapy_load[i].getlayer(Raw).load.split()
    
    if   not request_check[0] in [ 'GET', 'POST', 'PUT', 'HEAD' ] or \
    not any(item.startswith('HTTP/') for item in request_check) or \
    not any(item.startswith('User-Agent:') for item in request_check) or \
    not any(item.startswith('Host:') for item in request_check):
      print "Has NO HTTP request within GET,POST,PUT,HEAD ! \n \
      OR \n \
      NOT a proper HTTP request !! \n \
      Skipping.... "
      #we explicitly empty the list
      request_check[:] = []
      continue
    
    #we explicitly empty the list
    request_check[:] = []
    yield i
    
  


if __name__ == "__main__":
  
  
  Global_Vars.returnYamlOptions()
  Global_Vars.returnProcessesToStart(Global_Vars.yaml_options)
  Global_Vars.returnChunks(Global_Vars.yaml_options)
  
  
  Global_Vars.preRunChecks()
  Global_Vars.init_Pcap_Id()
  Global_Vars.load_The_Pcap()
  packet_index_ready = ReturnReadyPackets(Global_Vars.pcap_file_loaded)
  
  
  pool = multiprocessing.Pool(Global_Vars.processes_to_start)
  pool.imap(ReWriteAll , (packet_index_ready) , Global_Vars.chunks)
  pool.close()
  pool.join()
  
  

