from consolemenu import *
from consolemenu.items import *
import scapy.all as scapy
import socket
import sys
import nmap
import subprocess
import requests
from textwrap import wrap
import os
import time
import signal
from colorama import init, Fore, Style
import psutil


def network_scanner():
    def scan_network(ip_range):
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        live_hosts = []

        for element in answered_list:
            host_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            live_hosts.append(host_dict)

        return live_hosts

    def start():
        banner_text='''
    _   __     __                      __      _____                                 
   / | / /__  / /__      ______  _____/ /__   / ___/_________ _____  ____  ___  _____
  /  |/ / _ \/ __/ | /| / / __ \/ ___/ //_/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /|  /  __/ /_ | |/ |/ / /_/ / /  / ,<     ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/ |_/\___/\__/ |__/|__/\____/_/  /_/|_|   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                                                                                                                   

'''
        print("\033[91m" + banner_text + "\033[0m")
        target_ip_range = "192.168.239.0/24" 
        live_hosts = scan_network(target_ip_range)

        print("\033[92m\033[1mLive Hosts: \n")
        for host in live_hosts:
            try:
                hostname = socket.gethostbyaddr(host['ip'])[0]
            except socket.herror:
                hostname = "Unknown"
            print("IP: {}, MAC: {}, Hostname: {}".format(host['ip'], host['mac'], hostname))

    start()

    end = input("\n\033[91m\033[1mPress any key to close...")

pass


def port_scanner():

    def scanHost(ip, startPort, endPort):
           print('\n[*] Starting TCP port scan on host %s' % ip)
           # Begin TCP scan on host
           tcp_scan(ip, startPort, endPort)
           print('[+] TCP scan on host %s complete' % ip)

    def scanRange(network, startPort, endPort):
           print('[*] Starting TCP port scan on network %s.0' % network)
           for host in range(1, 255):
               ip = network + '.' + str(host)
               tcp_scan(ip, startPort, endPort)


           print('[+] TCP scan on network %s.0 complete' % network)

    def tcp_scan(ip, startPort, endPort):
       for port in range(startPort, endPort + 1):
           try:
               tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               if not tcp.connect_ex((ip, port)):
                   print('[+] %s:%d/TCP Open' % (ip, port))
                   tcp.close()
           except Exception:
               pass
          
    def start():
            
            banner_text='''
    ____             __     _____                                 
   / __ \____  _____/ /_   / ___/_________ _____  ____  ___  _____
  / /_/ / __ \/ ___/ __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ____/ /_/ / /  / /_    ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/    \____/_/   \__/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                                                                                                                                                                       

'''
            print("\033[91m" + banner_text + "\033[0m")
            socket.setdefaulttimeout(0.01)
            network = input("\033[92m\033[1mPlease enter IP Address: ")
            startPort = int(input("\nStart Port: "))
            endPort = int(input("End Port: "))
            print("\033[0m")

            scanHost(network, startPort, endPort)
  
    start()
    end = input("\n\033[91m\033[1mPress any key to close...")

pass


def service_version_detection():
  
    banner_text='''
   _____                 _              _    __               _           
  / ___/___  ______   __(_)_______     | |  / /__  __________(_)___  ____ 
  \__ \/ _ \/ ___/ | / / / ___/ _ \    | | / / _ \/ ___/ ___/ / __ \/ __ |
 ___/ /  __/ /   | |/ / / /__/  __/    | |/ /  __/ /  (__  ) / /_/ / / / /
/____/\___/_/    |___/_/\___/\___/     |___/\___/_/  /____/_/\____/_/ /_/ 
                                                                                                                                                                                                                                                                                                                                                       

'''
    print("\033[91m" + banner_text + "\033[0m")
    nm = nmap.PortScanner()
    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    nm.scan(ip, '1-1024')
  
    for host in nm.all_hosts():
        print(f"\nHost: {host}\n")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for lport in lport:
                try:
                    service_name = nm[host][proto][lport]['name']
                    product_info = nm[host][proto][lport].get('product', None)
                    if product_info:
                        product_version = product_info.split()[0]
                        print(f"Port {lport}: {service_name} version {product_version}")
                    else:
                        print(f"Port {lport}: {service_name} (No version information available)")
                except KeyError:
                    pass

    end = input("\n\033[91m\033[1mPress any key to close...")

pass


def banner_grabbing():
   
    banner_text='''
    ____                                 ______                    
   / __ )____ _____  ____  ___  _____   / ____/___  __  ______ ___ 
  / __  / __ `/ __ \/ __ \/ _ \/ ___/  / __/ / __ \/ / / / __ `__ |
 / /_/ / /_/ / / / / / / /  __/ /     / /___/ / / / /_/ / / / / / /
/_____/\__,_/_/ /_/_/ /_/\___/_/     /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                   

'''
    print("\033[91m" + banner_text + "\033[0m")  
    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")

    try:
        s = socket.socket()
        s.settimeout(2) 
        s.connect((ip, 80))
        s.send(b'GET / HTTP/1.1\r\n\r\n')

        banner = s.recv(1024).decode('utf-8')

        print(f"Banner for {ip}:{80}:\n{banner}")

    except socket.error as e:
        print(f"Error: {e}")
    finally:
        s.close()
  
    end = input("\033[91m\033[1mPress any key to close...")

pass


def website_vuln_scanner():
    banner_text=''' 
 _       __     __       _    __      __         _____                
| |     / /__  / /_     | |  / /_  __/ /___     / ___/_________ _____ 
| | /| / / _ \/ __ \    | | / / / / / / __ \    \__ \/ ___/ __ `/ __ `
| |/ |/ /  __/ /_/ /    | |/ / /_/ / / / / /   ___/ / /__/ /_/ / / / /
|__/|__/\___/_.___/     |___/\__,_/_/_/ /_/   /____/\___/\__,_/_/ /_/ 
                                                                                                                                       

'''
    print("\033[91m" + banner_text + "\033[0m")
  
    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"nikto -h {ip}"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")
  
    end = input("\033[91m\033[1mPress any key to close...")
pass


def smb_enumeration():

    banner_text='''
   _____ __  _______     ______                    
  / ___//  |/  / __ )   / ____/___  __  ______ ___ 
  \__ \/ /|_/ / __  |  / __/ / __ \/ / / / __ `__ `
 ___/ / /  / / /_/ /  / /___/ / / / /_/ / / / / / /
/____/_/  /_/_____/  /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                   

'''
    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"nmap -p 445,139 -sV -sC -O {ip}\n\n"

    print("\n\n\033[92m**********************************************************")
    print("\033[92m***************************NMAP***************************")
    print("\033[92m**********************************************************\n\n")
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    print("\n\n\033[92m**********************************************************")
    print("\033[92m************************ENUM4LINUX************************")
    print("\033[92m**********************************************************\n\n")

    command = f"enum4linux -a -u '' -p '' {ip}"
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing enum4linux command: {e.output}")

    print("\n\n\033[92m**********************************************************")
    print("\033[92m**************************Smbmap**************************")
    print("\033[92m**********************************************************\n\n")

    command = f"smbmap -u '' -p '' -H {ip}"
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing smbmap command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")

pass


def ftp_enumeration():

    banner_text=''' 
    ________________     ______                    
   / ____/_  __/ __ \   / ____/___  __  ______ ___ 
  / /_    / / / /_/ /  / __/ / __ \/ / / / __ `__ `
 / __/   / / / ____/  / /___/ / / / /_/ / / / / / /
/_/     /_/ /_/      /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                                                     

'''

    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"nmap -vv --reason -Pn -T4 -sV -p 21 '--script=banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' {ip}\n\n"

    print("\n\n\033[92m**********************************************************")
    print("\033[92m***************************FTP****************************")
    print("\033[92m**********************************************************\n\n")
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")

pass


def ssh_enumeration():

    banner_text=''' 
   __________ __  __   ______                    
  / ___/ ___// / / /  / ____/___  __  ______ ___ 
  \__ \\__ \/ /_/ /  / __/ / __ \/ / / / __ `__ `
 ___/ /__/ / __  /  / /___/ / / / /_/ / / / / / /
/____/____/_/ /_/  /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                                                                                                   

'''
    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"nmap -vv --reason -Pn -T4 -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {ip}\n\n"

    print("\n\n\033[92m**********************************************************")
    print("\033[92m**********************SSH Enumeration*********************")
    print("\033[92m**********************************************************\n\n")
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")

pass


def directory_bruteforcing():

    banner_text=''' 
   ______      __               __           
  / ____/___  / /_  __  _______/ /____  _____
 / / __/ __ \/ __ \/ / / / ___/ __/ _ \/ ___/
/ /_/ / /_/ / /_/ / /_/ (__  ) /_/  __/ /    
\____/\____/_.___/\__,_/____/\__/\___/_/     
                                             

'''
    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"gobuster dir -u http://{ip}/ -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r \n\n"

    print("\n\n\033[92m**********************************************************")
    print("\033[92m*******************Directory Bruteforcing*****************")
    print("\033[92m**********************************************************\n\n")
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")

pass


def web_technology_enumerator():

    banner_text=''' 
    ____        _ ____     _       ___ __  __  
   / __ )__  __(_) / /_   | |     / (_) /_/ /_ 
  / __  / / / / / / __/   | | /| / / / __/ __ `
 / /_/ / /_/ / / / /_     | |/ |/ / / /_/ / / /
/_____/\__,_/_/_/\__/     |__/|__/_/\__/_/ /_/ 
                                               

'''
    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[0m")
    command = f"whatweb {ip} --verbose \n\n"

    print("\n\n\033[92m**********************************************************")
    print("\033[92m*****************Web Technology Enumeration***************")
    print("\033[92m**********************************************************\n\n")
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")

pass


def run_all_scans():

    banner_text=''' 

    ___    ____   _____                      
   /   |  / / /  / ___/_________ _____  _____
  / /| | / / /   \__ \/ ___/ __ `/ __ \/ ___/
 / ___ |/ / /   ___/ / /__/ /_/ / / / (__  ) 
/_/  |_/_/_/   /____/\___/\__,_/_/ /_/____/  
                                                                                        

'''
    print("\033[91m" + banner_text + "\033[0m")

    ip = input("\033[92m\033[1mPlease enter the IP address: ")
    print("\033[92m\033[1mRunning all scans on provided IP!")
    
    os.mkdir('results')

    # Port Scanner
    print("\n\n\033[92m**********************************************************")
    print("\033[92m************************Port Scanner**********************")
    print("\033[92m**********************************************************\n\n")
    print("\033[0m")
    

    socket.setdefaulttimeout(0.01)
    startPort = 1
    endPort = 10000
    
    for port in range(startPort, endPort + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if not tcp.connect_ex((ip, port)):
                print('[+] %s:%d/TCP Open' % (ip, port))
                tcp.close()
        except Exception:
            pass

    # Service Version Detection
    print("\n\n\033[92m**********************************************************")
    print("\033[92m*****************Service Version Detection****************")
    print("\033[92m**********************************************************\n\n")

    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for lport in lport:
                try:
                    service_name = nm[host][proto][lport]['name']
                    product_info = nm[host][proto][lport].get('product', None)
                    if product_info:
                        product_version = product_info.split()[0]
                        print(f"Port {lport}: {service_name} version {product_version}")
                    else:
                        print(f"Port {lport}: {service_name} (No version information available)")
                except KeyError:
                    pass

    # Banner Grabbing
    print("\n\n\033[92m**********************************************************")
    print("\033[92m**********************Banner Grabbing*********************")
    print("\033[92m**********************************************************\n\n")
    
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, 80))
        s.send(b'GET / HTTP/1.1\r\n\r\n')
        banner = s.recv(1024).decode('utf-8')
        print(f"Banner for {ip}:{80}:\n{banner}")
    except socket.error as e:
        print(f"Error: {e}")
    finally:
        s.close()

    # Website Vulnerability Scanning
    print("\n\n\033[92m**********************************************************")
    print("\033[92m**************Website Vulnerability Scanning**************")
    print("\033[92m**********************************************************\n\n")

    os.mkdir('results/web')
    command = f"nikto -h {ip} | tee results/web/nikto_web_vuln_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

    # SMB Enumeration
    print("\n\n\033[92m**********************************************************")
    print("\033[92m**********************SMB Enumeration*********************")
    print("\033[92m**********************************************************\n\n")
    
    os.mkdir('results/smb')
    command = f"nmap -p 445 -sV -sC -O {ip} | tee ./results/smb/smb_nmap_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    command = f"enum4linux -a -u '' -p '' {ip} | tee ./results/smb/smb_enum4linux_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing enum4linux command: {e.output}")

    command = f"smbmap -u '' -p '' -H {ip} | tee ./results/smb/smb_smbmap_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing enum4linux command: {e.output}")

    # FTP Enumeration
    
    print("\n\n\033[92m**********************************************************")
    print("\033[92m***************************FTP****************************")
    print("\033[92m**********************************************************\n\n")
    
    os.mkdir('results/ftp')
    command = f"nmap -vv --reason -Pn -T4 -sV -p 21 '--script=banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' {ip} | tee ./results/ftp/ftp_nmap_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    # SSH Enumeration
    print("\n\n\033[92m**********************************************************")
    print("\033[92m**********************SSH Enumeration*********************")
    print("\033[92m**********************************************************\n\n")
    os.mkdir('results/ssh')
    command = f"nmap -vv --reason -Pn -T4 -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {ip} | tee ./results/ssh/ssh_nmap_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e.output}")

    # Directory Bruteforcing
    print("\n\n\033[92m**********************************************************")
    print("\033[92m*******************Directory Bruteforcing*****************")
    print("\033[92m**********************************************************\n\n")
    
    command = f"gobuster dir -u http://{ip}/ -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r | tee ./results/web/gobuster_dirbursting_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing gobuster command: {e.output}")

    # Web Technology Enumeration
    print("\n\n\033[92m**********************************************************")
    print("\033[92m*****************Web Technology Enumeration***************")
    print("\033[92m**********************************************************\n\n")

    
    command = f"whatweb {ip} --verbose | tee ./results/web/whatweb_web_technology_scan.txt"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing whatweb command: {e.output}")

    end = input("\033[91m\033[1mPress any key to close...")


def service_bruteforce():
    class ServiceBruteforce:

        def __init__(self):
            pass

        def bruteforce(self):

            banner='''

   _____                 _              ____             __       ____                         
  / ___/___  ______   __(_)_______     / __ )_______  __/ /____  / __/___  _____________  _____
  \__ \/ _ \/ ___/ | / / / ___/ _ \   / __  / ___/ / / / __/ _ \/ /_/ __ \/ ___/ ___/ _ \/ ___/
 ___/ /  __/ /   | |/ / / /__/  __/  / /_/ / /  / /_/ / /_/  __/ __/ /_/ / /  / /__/  __/ /    
/____/\___/_/    |___/_/\___/\___/  /_____/_/   \__,_/\__/\___/_/  \____/_/   \___/\___/_/     
                                                                                               

'''

            print("\033[91m" + banner + "\033[0m")
            ip = input("\033[92m\033[1mPlease enter the IP address: ")
            service_type = input("\n\033[92m\033[1mEnter the service type (ftp, ssh, smb, http): ")
            print("\033[0m")

            if service_type == "ftp":
                username_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                password_list = "/usr/share/seclists/Passwords/darkweb2017-top100.txt"
                command = f"hydra -L {username_list} -P {password_list} -I -e nsr -s 21 ftp://{ip}"
            elif service_type == "ssh":
                username_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                password_list = "/usr/share/seclists/Passwords/darkweb2017-top100.txt"
                command = f"hydra -L {username_list} -P {password_list} -I -e nsr -s 22 ssh://{ip}"
            elif service_type == "smb":
                username_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                password_list = "/usr/share/seclists/Passwords/darkweb2017-top100.txt"
                command = f"hydra -L {username_list} -P {password_list} -I -s 445 -t 32 smb://{ip}"
            elif service_type == "http":
                path = input("\033[92m\033[1mEnter the path to bruteforce: ")
                print("\033[0m")
                username_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                password_list = "/usr/share/seclists/Passwords/darkweb2017-top100.txt"
                command = f"hydra -L {username_list} -P {password_list} -I -e nsr -s 80 http-get://{ip}/{path}"
            else:
                print("Invalid service type")
                return

            process = subprocess.Popen(command, shell=True)
            process_pid = process.pid
            parent = None

            try:
                while True:
                    user_input = input("Press 'q' and 'Enter' to stop the brute force\n")
                    if user_input.lower() == 'q':
                        parent = psutil.Process(process_pid)
                        for child in parent.children(recursive=True):
                            child.terminate()
                        parent.terminate()
                        time.sleep(1)
                        print("\n\033[91m\033[1mBruteforce Interrupted")
                        break
            except subprocess.CalledProcessError as e:
                print(f"Error: {e.output}")
            except Exception as e:
                print(f"Unexpected error: {e}")
            finally:
                if parent is not None and parent.is_running():
                    parent.terminate()

            process.wait()  # Wait for the process to complete
           

    service_bruteforce = ServiceBruteforce()
    service_bruteforce.bruteforce()

    end = input("\n\033[91m\033[1mPress any key to close...")
pass


init(autoreset=True)
banner= '''

\033[1m ______                             ______            _ _           \033[0m
\033[1m(_____ \                           / _____) _        (_) |          \033[0m
\033[1m _____) )_____  ____ ___  ____    ( (____ _| |_  ____ _| |  _ _____ \033[0m
\033[1m|  __  /| ___ |/ ___) _ \|  _ \    \____ (_   _)/ ___) | |_/ ) ___ |\033[0m
\033[1m| |  \ \| ____( (__| |_| | | | |   _____) )| |_| |   | |  _ (| ____|\033[0m
\033[1m|_|   |_|_____)\____)___/|_| |_|  (______/  \__)_|   |_|_| \_)_____)\033[0m
                                                                    
                                                      
--------------------------------------------------------------------
                 [ Reconnaisance Toolkit - v1.0.0 ]


'''

menu = ConsoleMenu(banner, "")

function_item1 = FunctionItem("Network Scanner", network_scanner)
function_item2 = FunctionItem("Port Scanner", port_scanner)
function_item3 = FunctionItem("Service Version Detection", service_version_detection)
function_item4 = FunctionItem("Banner Grabbing", banner_grabbing)
function_item5 = FunctionItem("Website Vulnerability Scanning", website_vuln_scanner)
function_item6 = FunctionItem("SMB Enumeration", smb_enumeration)
function_item7 = FunctionItem("FTP Enumeration", ftp_enumeration)
function_item8 = FunctionItem("SSH Enumeration", ssh_enumeration)
function_item9 = FunctionItem("Directory Bruteforcing", directory_bruteforcing)
function_item10 = FunctionItem("Web Technology Enumeration", web_technology_enumerator)
function_item11 = FunctionItem("Service Bruteforcer", service_bruteforce)
function_item12 = FunctionItem("Run All Scans", run_all_scans)

menu.append_item(function_item1)
menu.append_item(function_item2)
menu.append_item(function_item3)
menu.append_item(function_item4)
menu.append_item(function_item5)
menu.append_item(function_item6)
menu.append_item(function_item7)
menu.append_item(function_item8)
menu.append_item(function_item9)
menu.append_item(function_item10)
menu.append_item(function_item11)
menu.append_item(function_item12)


menu.show()



