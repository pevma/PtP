#!/usr/bin/python
# -*- coding: utf-8 -*-


##                                       ##
# Author: Peter Manev                     #
# peter.manev@openinfosecfoundation.org   #
##                                       ##


## !!! IMPORTANT - LATEST DEV Scapy is needed !!!
# REMOVE your current scapy installation !!!
# then ->
# hg clone http://hg.secdev.org/scapy-com
# python setup.py install


from scapy.all import *
import sys, urllib , os, subprocess, random, string
from itertools import *
import Global_Vars


class pacifyIpv4Icmp:
  
  
  def writeIPv4IcmpRule(self, sid_id_icmp, icmp_content_match_string, \
  directory, src_name):
    ##creating and writing a sid.rules file
    rule_file = open('%s/%s.rules' % (directory,sid_id_icmp), 'w+')
    
    content_all_ready_for_rule = None
    content_all_ready_for_rule = ""
    
    if (len(icmp_content_match_string) > 250):
      
      content_icmp_all_array = [icmp_content_match_string[i:i+250] for i in range(0, len(icmp_content_match_string), 250)] 
      
      for i in content_icmp_all_array:
	
        i = i.replace('|', '|7C|').replace('"', '|22|').replace(';', '|3B|').\
        replace(':', '|3A|').replace(' ', '|20|').replace('\\', '|5C|').\
        replace('\'', '|27|').replace('\r', '|0d|').replace('\n', '|0a|')
        
        content_all_ready_for_rule = \
        content_all_ready_for_rule + \
        ("content:\"%s\"; " % (i))
        
      
    else:
      
      icmp_content_match_string = icmp_content_match_string.replace('|', '|7C|').\
      replace('"', '|22|').replace(';', '|3B|').replace(':', '|3A|').\
      replace(' ', '|20|').replace('\\', '|5C|').replace('\'', '|27|').\
      replace('\r', '|0d|').replace('\n', '|0a|')
      
      content_all_ready_for_rule = \
      ("content:\"%s\"; " % (icmp_content_match_string))
      
    
    rule_file.write ( \
    "alert icmp any any -> any any (msg:\"IP tests - sid %s , pcap - %s \"; \
    %s reference:url,%s; sid:%s; rev:1;)" % \
    (sid_id_icmp, sid_id_icmp, content_all_ready_for_rule, src_name, \
    sid_id_icmp) )
    
    rule_file.close()


  def rebuildIPv4IcmpSession(self, packet, results_directory, sid_id_icmp, \
  src_name, repo_name):
    session_packets = list()
    session_packets_fragmented = list()
    
    
    ipsrc = packet[IP].src
    ipdst = packet[IP].dst
    
    
    
    
    ICMP1 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    self.icmp_Random_Data()

    ICMP2 =  Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    ICMP1[ICMP][Raw]

    ICMP3 =  Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    
    ##This is the actual data packet that will be send, containing the payload
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    
    ##This is the actual data packet that will be send, containing the payload
    #- fragmented
    p_frag =  fragment(p, fragsize=10 )
    
    
    ICMP5 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    self.icmp_Random_Data()
    
    
    ICMP6 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    ICMP5[ICMP][Raw]
    
    ICMP7 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 2))/ \
    self.icmp_Random_Data()
    
    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list
    
    
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list


  def rebuildIPv4IcmpSessionDot1Q(self, packet, results_directory, \
  sid_id_icmp, src_name, repo_name):
    
    #Dot1Q VLAN tags
    
    session_packets = list()
    session_packets_fragmented = list()
    
    
    ipsrc = packet[IP].src
    ipdst = packet[IP].dst
    
    
    ICMP1 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    self.icmp_Random_Data()
    ICMP1.tags = Dot1Q(vlan=1111)

    ICMP2 =  Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    ICMP1[ICMP][Raw]
    ICMP2.tags = Dot1Q(vlan=1111)

    ICMP3 =  Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    ICMP3.tags = Dot1Q(vlan=1111)
    
    
    ##This is the actual data packet that will be send, containing the payload
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p.tags = Dot1Q(vlan=1111)

    ##This is the actual data packet that will be sent containing the payload
    #- fragmented
    p_frag =  fragment(p, fragsize=10 )

    ## This is the same original data packet - but no VLAN tags
    p_Dot1Q_untagged = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]

    p_frag_Dot1Q_untagged = fragment(p_Dot1Q_untagged, fragsize=10)
    
    # Dot1Q wrong VLAN tag - we change the VLAN tag in the data packet
    # Everything else is the same and stays the same
    p_Dot1Q_tagged_wrong = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p_Dot1Q_tagged_wrong.tags = Dot1Q(vlan=3333)
    
    ##This is the actual data packet that will be sent containing the payload
    #- fragmented.
    p_frag_Dot1Q_tagged_wrong = fragment(p_Dot1Q_tagged_wrong, fragsize=10 )
    
    ##This is the data packet. Fromt this data packet we will edit and tweek
    # the VLAN tags for one or more fragments of the same data packet !
    p_Dot1Q_data_frag = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p_Dot1Q_data_frag.tags = Dot1Q(vlan=1111)
    
    # We fragment the data packet, then we will play around with the fragments
    # VLAN tags
    p_frag_Dot1Q_data_frag_wrong = fragment(p_Dot1Q_data_frag, fragsize=10 )
    p_frag_Dot1Q_data_frag_wrong[3].tags = Dot1Q(vlan=3333)
    
    # We fragment the data packet , but we make one fragment untagged.
    # VLAN tag missing
    p_frag_Dot1Q_data_frag_missing = fragment(p_Dot1Q_data_frag, fragsize=10 )
    p_frag_Dot1Q_data_frag_missing[3].tags = Untagged()

    # We fragment the data packet , but we make  ONLY one fragment tagged
    # with the correct VLAN tag
    p_frag_Dot1Q_data_frag_one_tagged = fragment(p_Dot1Q_data_frag, fragsize=10 )
    for frag in p_frag_Dot1Q_data_frag_one_tagged:
      frag.tags = Untagged()
    p_frag_Dot1Q_data_frag_one_tagged[3].tags = Dot1Q(vlan=1111)
    
    
    ICMP5 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    self.icmp_Random_Data()
    ICMP5.tags =  Dot1Q(vlan=1111)
    
    
    ICMP6 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    ICMP5[ICMP][Raw]
    ICMP6.tags = Dot1Q(vlan=1111)
    
    ICMP7 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 2))/ \
    self.icmp_Random_Data()
    ICMP7.tags = Dot1Q(vlan=1111)
    
    
    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Dot1Q-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list
    
    
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q-%s-tp-02.pcap"\
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q-%s-tp-02.pcap"\
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    ##
    # Here we start with the wrong Dot1Q VLAN tags in the data packet
    # and the creation of the pcaps designed for not alerting
    # due to changed (fake/hopped) VLAN tag in the same flow
    ##
    
    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p_Dot1Q_tagged_wrong)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Dot1Q_tagged_wrong-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list
    
    
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_Dot1Q_tagged_wrong:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q_tagged_wrong-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_Dot1Q_tagged_wrong):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q_tagged_wrong-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_Dot1Q_tagged_wrong)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_Dot1Q_tagged_wrong:
      session_packets_fragmented.append(p_fragment)
      
    
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q_tagged_wrong-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    ##
    # Here we start with the missing Dot1Q VLAN tag in the data packet
    # and the creation of the pcaps designed for not alerting
    # due to missing VLAN tag in the same flow.
    ##

    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p_Dot1Q_untagged)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Dot1Q_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list


    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_Dot1Q_untagged:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_Dot1Q_untagged):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_Dot1Q_untagged)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_Dot1Q_untagged:
      session_packets_fragmented.append(p_fragment)

    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list


  def rebuildIPv4IcmpSessionDot1QWrongTagInFragments(self, packet, results_directory, \
  sid_id_icmp, src_name, repo_name):
    
    #Dot1Q VLAN tags
    #Here we will change the VLAN tags on one or more frgaments 
    #of the data packet
    
    session_packets = list()
    session_packets_fragmented = list()
    
    
    ipsrc = packet[IP].src
    ipdst = packet[IP].dst
    
    
    ICMP1 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    self.icmp_Random_Data()
    ICMP1.tags = Dot1Q(vlan=1111)

    ICMP2 =  Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    ICMP1[ICMP][Raw]
    ICMP2.tags = Dot1Q(vlan=1111)

    ICMP3 =  Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    ICMP3.tags = Dot1Q(vlan=1111)
    
    
    ##This is the actual data packet that will be send, containing the payload
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p.tags = Dot1Q(vlan=1111)
    
    ##This is the actual data packet that will be sent containing the payload
    #- fragmented
    p_frag =  fragment(p, fragsize=10 )
    
    ##This is the data packet. Fromt this data packet we will edit and tweek
    # the VLAN tags for one or more fragments of the same data packet !
    p_Dot1Q_data_frag = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p_Dot1Q_data_frag.tags = Dot1Q(vlan=1111)
    
    # We fragment the data packet, then we will play around with the fragments
    # VLAN tags - one fragment has the wrong VLAN tag
    p_frag_Dot1Q_data_frag_wrong = fragment(p_Dot1Q_data_frag, fragsize=10 )
    p_frag_Dot1Q_data_frag_wrong[3].tags = Dot1Q(vlan=3333)
    
    # We fragment the data packet , but we make one fragment untagged.
    # VLAN tag missing
    p_frag_Dot1Q_data_frag_missing = fragment(p_Dot1Q_data_frag, fragsize=10 )
    p_frag_Dot1Q_data_frag_missing[3].tags = Untagged()
    
    # We fragment the data packet , but we make  ONLY one fragment tagged
    # with the correct VLAN tag
    p_frag_Dot1Q_data_frag_one_tagged = fragment(p_Dot1Q_data_frag, fragsize=10 )
    for frag in p_frag_Dot1Q_data_frag_one_tagged:
      frag.tags = Untagged()
    p_frag_Dot1Q_data_frag_one_tagged[3].tags = Dot1Q(vlan=1111)
    
    
    ICMP5 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    self.icmp_Random_Data()
    ICMP5.tags =  Dot1Q(vlan=1111)
    
    
    ICMP6 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    ICMP5[ICMP][Raw]
    ICMP6.tags = Dot1Q(vlan=1111)
    
    ICMP7 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 2))/ \
    self.icmp_Random_Data()
    ICMP7.tags = Dot1Q(vlan=1111)
    
    
    ##
    # Here we start with chnaging the  Dot1Q VLAN tags in the FRAGMENTS
    # of the data packetand the creation of the pcaps designed for not alerting
    # due to missing VLAN tag in the fragments of data in the same flow.
    ##
    
    ## one fragment from the data packet has a missing VLAN tag
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_Dot1Q_data_frag_missing:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q_data_tag_missing_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_Dot1Q_data_frag_missing):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q_data_tag_missing_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_Dot1Q_data_frag_missing)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_Dot1Q_data_frag_missing:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q_data_tag_missing_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    ## one frgament from the data packet has the wrong VLAN tag
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_Dot1Q_data_frag_wrong:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q_data_tag_wrong_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_Dot1Q_data_frag_wrong):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q_data_tag_wrong_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_Dot1Q_data_frag_wrong)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_Dot1Q_data_frag_wrong:
      session_packets_fragmented.append(p_fragment)

    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q_data_tag_wrong_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    ## all frgaments from the data packet have no VLAN tags BUT one
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_Dot1Q_data_frag_one_tagged:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_Dot1Q_data_tag_one_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_Dot1Q_data_frag_one_tagged):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_Dot1Q_data_tag_one_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_Dot1Q_data_frag_one_tagged)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_Dot1Q_data_frag_one_tagged:
      session_packets_fragmented.append(p_fragment)

    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_Dot1Q_data_tag_one_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list



  def rebuildIPv4IcmpSessionQinQ(self, packet, results_directory, sid_id_icmp, src_name, repo_name):
    
    #Dot1Q double tags (vlans) = QinQ
    session_packets = list()
    session_packets_fragmented = list()
    
    
    ipsrc = packet[IP].src
    ipdst = packet[IP].dst
    
    
    ICMP1 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    self.icmp_Random_Data()
    ICMP1.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP1.tags[Dot1Q].tpid = 0x88a8

    ICMP2 =  Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    ICMP1[ICMP][Raw]
    ICMP2.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP2.tags[Dot1Q].tpid = 0x88a8

    ICMP3 =  Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    ICMP3.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP3.tags[Dot1Q].tpid = 0x88a8
    
    
    ##This is the actual data packet that will be send, containing the payload
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    p.tags[Dot1Q].tpid = 0x88a8
    
    ##This is the actual data packet that will be sent containing the payload
    #- fragmented
    p_frag =  fragment(p, fragsize=10 )

    ## This is the same original data packet - but no VLAN tags
    p_QinQ_untagged = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]

    p_frag_QinQ_untagged = fragment(p_QinQ_untagged, fragsize=10)
    
    # QinQ reversed - we reverse/switch the VLAN tags in the data packet
    # Everything else is the same and stays the same
    p_QinQ_tag_reversed = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p_QinQ_tag_reversed.tags = Dot1AD(vlan=4094)/Dot1Q(vlan=666)
    p_QinQ_tag_reversed.tags[Dot1Q].tpid = 0x88a8
    
    ##This is the actual data packet that will be sent containing the payload
    #- fragmented, QinQ reversed/siwtched tags
    p_frag_QinQ_tag_reversed = fragment(p_QinQ_tag_reversed, fragsize=10 )
    
    
    ICMP5 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    self.icmp_Random_Data()
    ICMP5.tags =  Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP5.tags[Dot1Q].tpid = 0x88a8
    
    ICMP6 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    ICMP5[ICMP][Raw]
    ICMP6.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP6.tags[Dot1Q].tpid = 0x88a8
    
    ICMP7 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 2))/ \
    self.icmp_Random_Data()
    ICMP7.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP7.tags[Dot1Q].tpid = 0x88a8
    
    
    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_QinQ-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list
    
    
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag:
      session_packets_fragmented.append(p_fragment)
    
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    
    ##
    # Here we start with the reversed QinQ VLAN tags
    # and the creation of the pcaps designed for not alerting
    # due to switched (fake) VLAN tags in the same flow
    ##
    
    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p_QinQ_tag_reversed)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_QinQ_tags_reversed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list
    
    
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_tag_reversed:
      session_packets_fragmented.append(p_fragment)
    
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_tags_reversed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_tag_reversed):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_tags_reversed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_tag_reversed)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_tag_reversed:
      session_packets_fragmented.append(p_fragment)
    
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_tags_reversed-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    

    ##
    # Here we start with the missing Dot1Q VLAN tag in the data packet
    # and the creation of the pcaps designed for not alerting
    # due to missing VLAN tag in the same flow
    ##

    #write the session - normal
    session_packets.append(ICMP1)
    session_packets.append(ICMP2)
    session_packets.append(ICMP3)
    session_packets.append(p_QinQ_untagged)
    session_packets.append(ICMP5)
    session_packets.append(ICMP6)
    session_packets.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_QinQ_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets)
    session_packets[:] = [] #empty the list


    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_untagged:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_untagged):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_untagged)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_untagged:
      session_packets_fragmented.append(p_fragment)

    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_tag_missing-%s-tp-02.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

  def rebuildIPv4IcmpSessionQinQWrongTagInFragments(self, packet, \
  results_directory, sid_id_icmp, src_name, repo_name):
    
    #QinQ VLAN tags - double tags
    #Here we will change the VLAN tags on one or more frgaments 
    #of the QinQ data packet
    
    session_packets = list()
    session_packets_fragmented = list()
    
    
    ipsrc = packet[IP].src
    ipdst = packet[IP].dst
    
    
    ICMP1 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    self.icmp_Random_Data()
    ICMP1.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP1.tags[Dot1Q].tpid = 0x88a8
    
    ICMP2 =  Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq - 1))/ \
    ICMP1[ICMP][Raw]
    ICMP2.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP2.tags[Dot1Q].tpid = 0x88a8

    ICMP3 =  Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    ICMP3.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP3.tags[Dot1Q].tpid = 0x88a8
    
    
    ##This is the actual data packet that will be send, containing the payload
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    p.tags[Dot1Q].tpid = 0x88a8
    
    ##This is the data packet. Fromt this data packet we will edit and tweek
    # the VLAN tags (QinQ) for one or more fragments of the same data packet !
    p_QinQ_data_frag = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq))/ \
    packet[ICMP][Raw]
    p_QinQ_data_frag.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    p_QinQ_data_frag.tags[Dot1Q].tpid = 0x88a8
    
    ## We fragment the data packet, then we will play around with the fragments
    # VLAN tags in QinQ
    # Here we change the VLAN tag of the inner Dot1Q layer
    p_frag_QinQ_data_frag_wrong_dot1q = fragment(p_QinQ_data_frag, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_dot1q[3].tags = Dot1AD(vlan=666)/Dot1Q(vlan=777)
    p_frag_QinQ_data_frag_wrong_dot1q[3].tags[Dot1Q].tpid = 0x88a8
    
    ## We fragment the data packet, then we will play around with the fragments
    # VLAN tags in QinQ
    # Here we change the VLAN tag of the outer 802.1AD layer
    p_frag_QinQ_data_frag_wrong_dot1ad = fragment(p_QinQ_data_frag, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_dot1ad[3].tags = Dot1AD(vlan=777)/Dot1Q(vlan=4094)
    p_frag_QinQ_data_frag_wrong_dot1ad[3].tags[Dot1Q].tpid = 0x88a8
    
    
    ## We fragment the data packet and make one fragment with both tags
    # having the wrong VLAN IDs
    p_frag_QinQ_data_frag_wrong_both = fragment(p_QinQ_data_frag, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_both[3].tags = Dot1AD(vlan=444)/Dot1Q(vlan=555)
    p_frag_QinQ_data_frag_wrong_both[3].tags[Dot1Q].tpid = 0x88a8
    
    
    ## We fragment the data packet , but we make one fragment untagged.
    # VLAN tags missing
    p_frag_QinQ_data_frag_missing_tags = fragment(p_QinQ_data_frag, fragsize=10 )
    p_frag_QinQ_data_frag_missing_tags[3].tags = Untagged()
    
    ## We fragment the data packet , but we make one fragment with reversed
    # VLAN tags
    p_frag_QinQ_data_frag_reversed_tags = fragment(p_QinQ_data_frag, fragsize=10 )
    p_frag_QinQ_data_frag_reversed_tags[3].tags = \
    Dot1AD(vlan=4094)/Dot1Q(vlan=666)
    p_frag_QinQ_data_frag_reversed_tags[3].tags[Dot1Q].tpid = 0x88a8
    
    
    ## We fragment the data packet , but we make  ONLY one fragment QinQ tagged
    # with the correct VLAN tags
    p_frag_QinQ_data_frag_one_tagged = fragment(p_QinQ_data_frag, fragsize=10 )
    for frag in p_frag_QinQ_data_frag_one_tagged:
      frag.tags = Untagged()
    p_frag_QinQ_data_frag_one_tagged[3].tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    p_frag_QinQ_data_frag_one_tagged[3].tags[Dot1Q].tpid = 0x88a8
    
    
    ICMP5 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    self.icmp_Random_Data()
    ICMP5.tags =  Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP5.tags[Dot1Q].tpid = 0x88a8
    
    ICMP6 = Ether(src=packet[Ether].src, dst=packet[Ether].dst ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 1))/ \
    ICMP5[ICMP][Raw]
    ICMP6.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP6.tags[Dot1Q].tpid = 0x88a8
    
    ICMP7 = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipdst, dst=ipsrc)/ICMP(type="echo-request", code=0, \
    id=packet[ICMP].id,  seq=(packet[ICMP].seq + 2))/ \
    self.icmp_Random_Data()
    ICMP7.tags = Dot1AD(vlan=666)/Dot1Q(vlan=4094)
    ICMP7.tags[Dot1Q].tpid = 0x88a8
    
    
    ##
    # Here we start with chnaging the  QinQ VLAN tags in the FRAGMENTS
    # of the data packetand the creation of the pcaps designed for not alerting
    # due to missing/reversed/nonexisting VLAN tags in the fragments of 
    # data in the same flow.
    ##

    ## one fragment from the data packet has a wrong VLAN tag - dot1Q tag.
    # The other tag (dot1AD- S-VLAN/Carrier VLAN) is correct
    # write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_wrong_dot1q:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_wrong_dot1q_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_wrong_dot1q):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_wrong_dot1q_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_wrong_dot1q)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_wrong_dot1q:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_wrong_dot1q_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list
    
    ## one fragment from the data packet has a wrong VLAN tag - dot1AD tag
    # -> S-VLAN/Carrier VLAN. The other tag (dot1q) is correct
    # write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_wrong_dot1ad:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_wrong_dot1ad_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_wrong_dot1ad):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_wrong_dot1ad_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_wrong_dot1ad)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_wrong_dot1ad:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_wrong_dot1ad_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    
    ## one frgament from the data packet has both VLAN tag IDs wrong
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_wrong_both:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_wrong_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_wrong_both):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_wrong_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_wrong_both)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_wrong_both:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_wrong_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    ## one fragment of the data packet has NO VLAN tags
    #write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_missing_tags:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_missing_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_missing_tags):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_missing_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_missing_tags)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_missing_tags:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_missing_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list


    ## one fragment of the data packet has both VLAN tags switched/reversed
    # write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_reversed_tags:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_reversed_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_reversed_tags):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_reversed_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_reversed_tags)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_reversed_tags:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_reversed_tags_in_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    ## one fragment of the data packet has both VLAN tags correct.
    # The rest do not.
    # write the session but with an ordered fragmented payload
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in p_frag_QinQ_data_frag_one_tagged:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Ordered_QinQ_data_frag_one_tagged_fragments-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session with reverse fragments order
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    for p_fragment in reversed(p_frag_QinQ_data_frag_one_tagged):
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Reversed_QinQ_data_frag_one_tagged_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list

    #write the session but with unordered/unsorted/mixed JUST fragmented
    #payload packets
    session_packets_fragmented.append(ICMP1)
    session_packets_fragmented.append(ICMP2)
    session_packets_fragmented.append(ICMP3)
    random.shuffle(p_frag_QinQ_data_frag_one_tagged)
    #shuffle JUST the fragments in the session
    for p_fragment in p_frag_QinQ_data_frag_one_tagged:
      session_packets_fragmented.append(p_fragment)
    session_packets_fragmented.append(ICMP5)
    session_packets_fragmented.append(ICMP6)
    session_packets_fragmented.append(ICMP7)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Session_Fragmented_Mixed_QinQ_data_frag_one_tagged_fragment-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), session_packets_fragmented)
    session_packets_fragmented[:] = [] #empty the list




  def midstreamIPv4Icmp(self, fragit, results_directory, sid_id_icmp, \
  src_name, repo_name):
    
    #forcing correct recalculation of the checksum
    del fragit[IP].chksum
    
    
    fragit_done = fragment(fragit, fragsize=10 )
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    fragit_done.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(fragit_done)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Regular'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    
  def midstreamIPv4IcmpDot1Q(self, fragit, results_directory, sid_id_icmp, \
  src_name, repo_name):
    #Using VLAN Tag - Dot1Q
    
    #forcing correct recalculation of the checksum
    del fragit[IP].chksum
    
    
    fragit[Ether].tags=Dot1Q(vlan=2222)
    
    #one midstream packet in Dot1Q
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Dot1Q-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit)
    
    fragit_done = fragment(fragit, fragsize=10 )
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_Dot1Q-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    fragit_done.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_Dot1Q-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(fragit_done)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_Dot1Q-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    
  def midstreamIPv4IcmpDot1QWrongTagInFragments(self, fragit, \
  results_directory, sid_id_icmp, src_name, repo_name):
    # Wrongly tagged fragments
    # Using VLAN Tag - Dot1Q
    
    #forcing correct recalculation of the checksum
    del fragit[IP].chksum
    
    
    fragit[Ether].tags = Dot1Q(vlan=2222)
    
    ##
    # one fragment has the wrong VLAN ID tag
    ##
    fragit_done_wrong_dot1q_tag = fragment(fragit, fragsize=10 )
    fragit_done_wrong_dot1q_tag[3].tags = Dot1Q(vlan=2299)
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_Dot1Q_data_tag_wrong_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_wrong_dot1q_tag)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    fragit_done_wrong_dot1q_tag.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_Dot1Q_data_tag_wrong_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_wrong_dot1q_tag)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(fragit_done_wrong_dot1q_tag)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_Dot1Q_data_tag_wrong_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_wrong_dot1q_tag)
    
    ##
    # one fragment has no VLAN ID tag
    ##
    fragit_done_no_dot1q_tag = fragment(fragit, fragsize=10 )
    fragit_done_no_dot1q_tag[3].tags = Untagged()
    
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_Dot1Q_data_tag_none_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_no_dot1q_tag)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    fragit_done_no_dot1q_tag.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_Dot1Q_data_tag_none_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_no_dot1q_tag)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(fragit_done_no_dot1q_tag)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_Dot1Q_data_tag_none_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'Dot1Q'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done_no_dot1q_tag)


  def midstreamIPv4IcmpQinQ(self, fragit, results_directory, sid_id_icmp, \
  src_name, repo_name):
    #Using DOUBLE VLAN Tagging - QinQ
    
    #Forcing correct recalculation of the checksum
    del fragit[IP].chksum
    
    
    fragit.tags = Dot1AD(vlan=3333)/Dot1Q(vlan=1)
    fragit.tags[Dot1Q].tpid = 0x88a8
    
    #one midstream packet in QinQ
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_QinQ-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit)

    fragit_done = fragment(fragit, fragsize=10 )
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    fragit_done.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(fragit_done)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ-%s-tp-01.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), fragit_done)
    
    
  def midstreamIPv4IcmpQinQWrongTagInFragments(self, fragit, \
  results_directory, sid_id_icmp, src_name, repo_name):
    #Wrongly tagged fragments 
    #Using DOUBLE VLAN Tagging - QinQ
    
    #forcing correct recalculation of the checksum
    del fragit[IP].chksum
    
    

    fragit.tags = Dot1AD(vlan=3333)/Dot1Q(vlan=1)
    fragit.tags[Dot1Q].tpid = 0x88a8
    
    ##
    # We fragment the data packet, we change the VLAN tag of 
    # the outer 802.1AD layer
    ##
    p_frag_QinQ_data_frag_wrong_dot1ad = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_dot1ad[3].tags = Dot1AD(vlan=3333)/Dot1Q(vlan=777)
    p_frag_QinQ_data_frag_wrong_dot1ad[3].tags[Dot1Q].tpid = 0x88a8
    
    ##
    # We fragment the data packet, we change the VLAN tag of 
    # the inner Dot1Q layer
    ##
    p_frag_QinQ_data_frag_wrong_dot1q = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_dot1q[3].tags = Dot1AD(vlan=777)/Dot1Q(vlan=1)
    p_frag_QinQ_data_frag_wrong_dot1q[3].tags[Dot1Q].tpid = 0x88a8
    
    ##
    # We fragment the data packet, we make one fragmanet tagged only 
    # with one VLAN
    ##
    p_frag_QinQ_data_frag_only_dot1q = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_only_dot1q[3].tags = Dot1Q(vlan=2345)
    
    ##
    # We fragment the data packet and make one fragment with both tags
    # having the wrong VLAN IDs
    ##
    p_frag_QinQ_data_frag_wrong_both = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_wrong_both[3].tags = Dot1AD(vlan=111)/Dot1Q(vlan=222)
    p_frag_QinQ_data_frag_wrong_both[3].tags[Dot1Q].tpid = 0x88a8

    
    ## 
    # We fragment the data packet , but we make one fragment untagged.
    # VLAN tags missing
    ##
    p_frag_QinQ_data_frag_missing_tags = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_missing_tags[3].tags = Untagged()

    ## 
    # We fragment the data packet , but we make one fragment with reversed
    # VLAN tags
    ##
    p_frag_QinQ_data_frag_reversed_tags = fragment(fragit, fragsize=10 )
    p_frag_QinQ_data_frag_reversed_tags[3].tags = Dot1AD(vlan=1)/Dot1Q(vlan=3333)
    p_frag_QinQ_data_frag_reversed_tags[3].tags[Dot1Q].tpid = 0x88a8

    
    ## 
    # We fragment the data packet, we change the VLAN tag of 
    # the outer 802.1AD layer
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_wrong_dot1ad_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1ad)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_wrong_dot1ad.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_wrong_dot1ad_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1ad)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_wrong_dot1ad)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_wrong_dot1ad_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1ad)
    

    ##
    # We fragment the data packet, we change the VLAN tag of 
    # the inner Dot1Q layer
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_wrong_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1q)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_wrong_dot1q.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_wrong_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1q)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_wrong_dot1q)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_wrong_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_dot1q)


    ## 
    # We fragment the data packet, we make one fragmanet tagged only 
    # with one VLAN
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_only_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_only_dot1q)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_only_dot1q.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_only_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_only_dot1q)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_only_dot1q)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_only_dot1q_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_only_dot1q)
    
    
    ##
    # We fragment the data packet and make one fragment with both tags
    # having the wrong VLAN IDs
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_wrong_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_both)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_wrong_both.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_wrong_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_both)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_wrong_both)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_wrong_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_wrong_both)
    
    
    ## 
    # We fragment the data packet , but we make one fragment untagged.
    # VLAN tags missing
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_missing_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_missing_tags)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_missing_tags.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_missing_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_missing_tags)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_missing_tags)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_missing_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_missing_tags)
    
    
    ## 
    # We fragment the data packet , but we make one fragment with reversed
    # VLAN tags
    ##
    #write the ordered fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Ordered_QinQ_data_frag_reversed_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_reversed_tags)
    
    #reverse the fragments !!!
    #permanent change to the list of fragments
    p_frag_QinQ_data_frag_reversed_tags.reverse()
    #write the reversed fragmented payload packet and write
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Reversed_QinQ_data_frag_reversed_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_reversed_tags)
    
    #shuffle(unorder/mix) the fragmented payload packet and write
    random.shuffle(p_frag_QinQ_data_frag_reversed_tags)
    wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream_Fragmented_Mixed_QinQ_data_frag_reversed_tags_in_fragment-%s-fp-00.pcap" \
    % (os.path.join(results_directory, 'Midstream', 'QinQ'), sid_id_icmp, self.incrementPcapId("byOne") \
    , src_name, repo_name), p_frag_QinQ_data_frag_reversed_tags)

  def reconstructIPv4IcmpPacket(self, packet):
    # here we make the original HTTP packet into a just TCP packet
    
    packet.chksum=None
    packet[TCP].chksum=None
    
    if packet.haslayer(IPv6):
      ipsrc = "1.1.1.1"
      ipdst = "9.9.9.9"
    else:
      ipsrc = packet[IP].src
      ipdst = packet[IP].dst
    
    p = Ether(src=packet[Ether].dst, dst=packet[Ether].src ) \
    /IP(src=ipsrc, dst=ipdst)/ICMP(type="echo-reply", code=0, id=12345, \
    seq=54321 )/packet[TCP][Raw]
    
    
    return p

  def icmp_Random_Data(self, size=5, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))
    

  def incrementPcapId(self, action):
    
    if action == "byOne":
      Global_Vars.pcap_id = Global_Vars.pcap_id+1
      return '{0:03}'.format(Global_Vars.pcap_id)
      
    elif action == "clear":
      Global_Vars.pcap_id = 000
      return '{0:03}'.format(Global_Vars.pcap_id)
      
    else:
	sys.exit("Invalid argument for function incrementPcapId()")


  def icmpReWrite(self, scapy_load, FN, pcap_id, results_directory, \
  source_name, sid_id_icmp, icmp_str, repository_name):
    
    # writing the icmp request packet to pcap
    # in regression script format
    # 2002031-001-sandnet-public-tp-01.pcap - example
    ## 001 - starts here ##
    
    
    ipv4_icmp_packet = self.reconstructIPv4IcmpPacket(scapy_load[FN])
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['WriteRule']:
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Rules'), source_name)
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoMidstream']['PseudoMidstream']:
      wrpcap("%s/%s-%s-%s_IPv4_ICMP_Midstream-%s-tp-01.pcap" \
      % (os.path.join(results_directory, 'Midstream', 'Regular'), sid_id_icmp, self.incrementPcapId("byOne"), \
      source_name, repository_name) , ipv4_icmp_packet)
      
      self.midstreamIPv4Icmp(ipv4_icmp_packet, \
      results_directory, sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Midstream', 'Regular'), source_name)
      
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoMidstream']['Dot1Q']:
      self.midstreamIPv4IcmpDot1Q(ipv4_icmp_packet, results_directory, \
      sid_id_icmp, source_name, repository_name)
      
      self.midstreamIPv4IcmpDot1QWrongTagInFragments(ipv4_icmp_packet, \
      results_directory, sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Midstream', 'Dot1Q'), source_name)
      
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoMidstream']['QinQ']:
      self.midstreamIPv4IcmpQinQ(ipv4_icmp_packet, results_directory, \
      sid_id_icmp, source_name, repository_name)
      
      self.midstreamIPv4IcmpQinQWrongTagInFragments(ipv4_icmp_packet, \
      results_directory, sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Midstream', 'QinQ'), source_name)
      
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoSession']['PseudoSession']:
      self.rebuildIPv4IcmpSession(ipv4_icmp_packet, results_directory, \
      sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Regular'), source_name)
      
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoSession']['Dot1Q']:
      self.rebuildIPv4IcmpSessionDot1Q(ipv4_icmp_packet, results_directory, \
      sid_id_icmp, source_name, repository_name)
      
      self.rebuildIPv4IcmpSessionDot1QWrongTagInFragments(ipv4_icmp_packet, \
      results_directory, sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'Dot1Q'), source_name)
      
    
    if Global_Vars.yaml_options['Protocols']['ICMP']['PseudoSession']['QinQ']:
      self.rebuildIPv4IcmpSessionQinQ(ipv4_icmp_packet, results_directory, \
      sid_id_icmp, source_name, repository_name)
      
      self.rebuildIPv4IcmpSessionQinQWrongTagInFragments(ipv4_icmp_packet, \
      results_directory, sid_id_icmp, source_name, repository_name)
      
      self.writeIPv4IcmpRule(sid_id_icmp, icmp_str, \
      os.path.join(results_directory, 'QinQ'), source_name)
      
    
    
  
  
  def __init__(self, scapy_load, FN, pcap_id, results_directory, \
  source_name, sid_id_icmp, icmp_str, repository_name):
    
    self.scapy_load_to_pass = scapy_load
    self.FN_to_pass = FN
    self.pcap_id_to_pass = pcap_id
    self.results_directory_to_pass = results_directory
    self.source_name_to_pass = source_name
    self.sid_id_icmp_to_pass = sid_id_icmp
    self.icmp_str_to_pass = icmp_str
    self.repository_name_to_pass = repository_name
    
    
    # if ICMP over IPv4 is enabled in yaml
    if Global_Vars.yaml_options['Protocols']['ICMP']['IPv4']:
      self.icmpReWrite( \
      self.scapy_load_to_pass, self.FN_to_pass, self.pcap_id_to_pass, \
      self.results_directory_to_pass, self.source_name_to_pass, \
      self.sid_id_icmp_to_pass, self.icmp_str_to_pass, \
      self.repository_name_to_pass \
    )

