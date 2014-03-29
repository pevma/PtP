#!/usr/bin/python
# -*- coding: utf-8 -*-


##                                       ##
# Author: Peter Manev                     #
# peter.manev@openinfosecfoundation.org   #
##                                       ##


#you need to 
#apt-get install tshark
## !!! IMPORTANT - LATEST DEV Scapy is needed !!!
# REMOVE your current scapy installation !!!
# then ->
# hg clone http://hg.secdev.org/scapy-com
# python setup.py install


import sys, urllib , os, subprocess, random
import yaml
from scapy.all import *
from ParseYamlConfig import parseYamlConfig




def init_Pcap_Id():
  global pcap_id
  pcap_id = 000

def load_The_Pcap():
  global pcap_file_loaded
  
  print "Provided pcap file is - " , sys.argv[1]
  pcap_file_checked = sys.argv[1]
  
  #check if pcap is there
  if not os.path.isfile(pcap_file_checked):
    sys.stderr.write('The supplied pcap file - %s - does not exist!!!\
    \n' % pcap_file_checked)
    sys.exit(1)
    
  
  pcap_file_loaded =  rdpcap(pcap_file_checked)
  #return pcap_file_loaded

def preRunChecks():
  global results_directory
  global source_name
  global repository_name
  
  if len(sys.argv) != 5:
    print sys.argv
    sys.stderr.write('Usage: \n \
    1. script name , \n \
    2. full path to pcap file , \n \
    3. full path to directory where results are wanted to be stored, \n \
    4. source name - \"a-z, A-Z, 0-9, _\" characters allowed only !!  \n \
    5. repository - \"private\" , \"public\" , \"PRIVATE\" or \"PUBLIC\" \n \n \
    EXAMPLE: python PacifyThePcap.py ../pcaps-and-misc/test.pcap ../TEST TestCasses private \
    \n \n ' )
    sys.exit(1)
  
  print "Provided directory for results is - " , sys.argv[2]
  results_directory = sys.argv[2]
  
  print "Provided name for source is - ", sys.argv[3]
  source_name = sys.argv[3]
  
  #check if pcap to be name is in correct syntax
  #for the regression script
  if not (re.match('^[a-zA-Z0-9_]*$',source_name)):
    sys.stderr.write('The supplied source name - %s - is not within syntax!!' \
    % source_name)
    
    sys.stderr.write('\nPlease use only \" a-z A-Z 0-9 _ \" characters !!\n')
    sys.exit(1)
    
  print "Provided name for the repository is - ", sys.argv[4]
  repository_name = sys.argv[4]
  
  #check if repository name is in correct syntax
  #for the regression script - private, public, PRIVATE or PUBLIC
  if not (re.match('(public|private|PUBLIC|PRIVATE)',repository_name)):
    sys.stderr.write('The supplied repository name - %s - is not within syntax!!' \
    % repository_name)
    
    sys.stderr.write('\nPlease use only \"private\" , \"public\" , \"PRIVATE\" or \"PUBLIC\"  words !!\n \n')
    sys.exit(1)
  
  
  #check if dir exists, if not
  #create it
  if not os.path.exists(results_directory):
    print "Main directory does not exist - therefore - created.... \n  %s" % \
    results_directory
    os.makedirs(results_directory)
    
  #Python documentation - os.path.join()
  #If any component is an absolute path, all previous components 
  #(on Windows, including the previous drive letter, if there was one) 
  #are thrown away, and joining continues. 
  if not os.path.exists(os.path.join(results_directory, 'Midstream')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Midstream')
    os.makedirs(os.path.join(results_directory, 'Midstream'))
    
  if not os.path.exists(os.path.join(results_directory, 'Midstream', 'Dot1Q')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Midstream', 'Dot1Q')
    os.makedirs(os.path.join(results_directory, 'Midstream', 'Dot1Q'))
    
  if not os.path.exists(os.path.join(results_directory, 'Midstream', 'QinQ')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Midstream', 'QinQ')
    os.makedirs(os.path.join(results_directory, 'Midstream', 'QinQ'))
    
  if not os.path.exists(os.path.join(results_directory, 'Midstream', 'Regular')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Midstream', 'Regular')
    os.makedirs(os.path.join(results_directory, 'Midstream', 'Regular'))
    
  if not os.path.exists(os.path.join(results_directory, 'Dot1Q')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Dot1Q')
    os.makedirs(os.path.join(results_directory, 'Dot1Q'))
  
  if not os.path.exists(os.path.join(results_directory, 'QinQ')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'QinQ')
    os.makedirs(os.path.join(results_directory, 'QinQ'))
  
  if not os.path.exists(os.path.join(results_directory, 'Regular')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Regular')
    os.makedirs(os.path.join(results_directory, 'Regular'))
    
  if not os.path.exists(os.path.join(results_directory, 'Rules')):
    print "SubDirectory does not exist - therefore - created.... \n  %s" % \
    os.path.join(results_directory, 'Rules')
    os.makedirs(os.path.join(results_directory, 'Rules'))
  
  
  
  
def returnYamlOptions():
  global yaml_options
  yaml_options = parseYamlConfig().parseYaml()
  
  
def returnProcessesToStart(yaml_options):
  global processes_to_start
  processes_to_start = parseYamlConfig().getProcesses(yaml_options)
  
  
def returnChunks(yaml_options):
  global chunks
  chunks = parseYamlConfig().getChunks(yaml_options)
  
  
  

