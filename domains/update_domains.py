from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

import json

domains = []
domains_file = []

f = open("avail-domains.txt")
for line in f.readlines():
    if '#' not in line:
        domains.append(line.strip())
    f.close()

for d in domains:
    try:
        answer = sr1(
            IP(dst="127.0.0.1") / UDP(sport=RandShort(), dport=53) / DNS(id=12456, rd=1, qd=DNSQR(qname=d)),
            verbose=0)
        info = {
            "dominio": str(d),
            "ip": str(answer[DNS].an.rdata)
        }
        domains_file.append(info)
    except Exception as e:
        print(d, e)

f = open('../client/dns.json', "w")
json.dump(domains_file, f)
f.close()
