from __future__ import print_function, unicode_literals
from os import walk
import sys
import argparse
import string
from datetime import datetime
from threading import Thread
import time
from netmiko import ConnectHandler

from multiprocessing.pool import ThreadPool
backup_dir = "/backups_cisco/"

#TODO this module handles the interaction with the devices and detects if the Router is VULN to EPC Tapping

def ssh_establisher(host,user,password):
    #USE ONLY ON YOUR OWN DEVICES 
    #THIS ALLWOS YOU TO PATCH THE SMI VECTOR
    cisco_device = {
    'device_type': 'cisco_ios',
    'ip':    host,
    'username': str(user),
    'password': str(password),
    'port' : 22,          # optional, defaults to 22
    'secret':  str(password),     # optional, defaults to ''
    'verbose': True,       # optional, defaults to False
    }
    try:
       net_connect = ConnectHandler(**cisco_device)
       #net_connect.find_prompt()
       output = net_connect.send_config_set("no vstack")
       if output:
          print(output)
       net_connect.exit_enable_mode()
       net_connect.disconnect()
       return output.split()
    except:
        pass
    

 
  
 

def backup_config(host,user,password,port):
    cisco_device = {
    'device_type': 'cisco_ios',
    'ip':    host,
    'username': str(user),
    'password': str(password),
    'port' : port,
    'secret':  str(password),
    'verbose': True,
    }
    try:
       net_connect = ConnectHandler(**cisco_device)
       output = net_connect.send_command("show configuration", delay_factor=2)
       net_connect.exit_enable_mode()
       filename = host+'--' + '{0:%Y-%m-%d-%H-%M-%S}'.format(datetime.datetime.now()) + '.txt'
       f = open(backup_dir +host+ '/' + filename, 'w')
       f.write(output)
       f.close()
    except:
       net_connect = ConnectHandler(**cisco_device)
       net_connect.enable()
       output = net_connect.send_command("show running-config")
       net_connect.exit_enable_mode()
       filename = host+'--' + '{0:%Y-%m-%d-%H-%M-%S}'.format(datetime.datetime.now()) + '.txt'
       f = open(backup_dir +host+ '/' + filename, 'w')
       f.write(output)
       f.close()
       f.write(output)
       f.close()


def detect_epc_tap_capabilities(host,user,password):
    #USE ONLY ON YOUR OWN DEVICES 
    #this allows you to check for tapping capabillities
    cisco_device = {
    'device_type': 'cisco_ios',
    'ip':    host,
    'username': str(user),
    'password': str(password),
    'port' : 22,          # optional, defaults to 22
    'secret':  str(password),     # optional, defaults to ''
    'verbose': True,       # optional, defaults to False
    }
    try:
       net_connect = ConnectHandler(**cisco_device)
       output = net_connect.send_config_set("do monitor capture buffer ?")
       
       if "% Incomplete command." in output:
           print(output)
           print("Target:"+host+ " is Vulnerable To EPC Tapping See Mimosa Framework for POC\n")
           net_connect.exit_enable_mode()
           net_connect.disconnect()
           return True
             
        
    except:
        return False
    

   
def cisc0_pwn3r(host,user,password,port):  
    if "22"  in port:
        try:
            #patch it from threat actors
            pool = ThreadPool(processes=2)
            async_result = pool.apply_async(ssh_establisher, (host,user,password)) 
            data_ret = async_result.get()
            if data_ret:
               try:
                   #determine if target is vulnerable to EPC attack!
                   pool = ThreadPool(processes=2)
                   async_result = pool.apply_async(detect_epc_tap_capabilities, (host,user,password))
                   is_vulnerable = async_result.get()
                   if is_vulnerable == True:
                      return is_vulnerable
                    
                   if is_vulnerable == False:
                      return is_vulnerable
               except:
                   pass
       
        except:
           pass



