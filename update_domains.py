from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

import json

f = open('dns.json')
data = json.load(f)
f.close()

for d in data:
    answer = sr1(
        IP(dst="127.0.0.1") / UDP(sport=RandShort(), dport=53) / DNS(id=12456, rd=1, qd=DNSQR(qname=d['dominio'])),
        verbose=0)
    print(answer[DNS].an.rdata)
    d['ip'] = answer[DNS].an.rdata

f = open('dns.json', "w")
json.dump(data, f)
f.close()
