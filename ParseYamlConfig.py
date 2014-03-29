#!/usr/bin/python
# -*- coding: utf-8 -*-

#you need to 
#sudo apt-get install python-yaml
#!!!! -- for this to work --!!!!

import multiprocessing
import yaml
import time, sys, os

class parseYamlConfig:
  
  # Important - by default python-yaml returns "True" or "Flase"
  # for any options set to "yes" or "no" and NOT the "yes" or "no" themselves
  
  def parseYaml(self):
    try:
      f = open('PacifyConfig.yaml', 'r')
    except IOError as e:
      print "I/O error({0}): {1}".format(e.errno, e.strerror), "ERROR !!!"
    
    self.dataMap = yaml.load(f)
    f.close()
    
    if not self.dataMap['Threads']['number_of_threads'] or not \
    ((str((self.dataMap['Threads']['number_of_threads']))).isdigit() or \
    self.dataMap['Threads']['number_of_threads'] == "auto"):
      print "NUMBER_OF_THREADS in the YAML configuration must be set to a digit or auto !!!"
      print "EXITING"
      sys.exit(1)
      
    if not self.dataMap['Threads']['chunks'] or not \
    ((str((self.dataMap['Threads']['chunks']))).isdigit() or \
    self.dataMap['Threads']['chunks'] == "auto" ):
      print "CHUNKS in the YAML configuration must be set to a" \
      " digit or auto !!!"
      print "Check your spelling. EXITING"
      sys.exit(1)
      
    return self.dataMap
    
  
  
  def getProcesses(self,yaml_options):
    
    if yaml_options['Threads']['number_of_threads'] == "auto":
      processes_to_start = multiprocessing.cpu_count()
      return processes_to_start
    else:
      processes_to_start = yaml_options['Threads']['number_of_threads']
      return processes_to_start
      
    
  
  
  def getChunks(self,yaml_options):
    
    if yaml_options['Threads']['chunks'] == "auto":
      chunks = 5
      return chunks
    else:
      chunks = yaml_options['Threads']['chunks']
      return chunks
  
  
  


