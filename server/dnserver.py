import logging
import os
import signal
from datetime import datetime
from time import sleep

from configparser import ConfigParser
config = ConfigParser()
config.read('configuration.ini')

from dnslib import QTYPE, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

from crypt.crypt import Crypt

SERIAL_NO = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}


class Resolver(ProxyResolver):
    def __init__(self, upstream):
        super().__init__(upstream, 53, 5)
        self.framestore = []
        self.number = 0
        self.length = 0
        self.current = 0
        self.current_i = 0
        self.pattern = -1

    def countConsonants(self, string):
        vowel = set("aeiouAEIOU")
        c_count = 0
        v_count = 0
        for i in string:
            if i in vowel:
                v_count += 1
            elif ('a' <= i <= 'z') or ('A' <= i <= 'Z'):
                c_count += 1

        return c_count, v_count

    def save_on_file(self, payload):
        self.framestore = []

        try:
            message = Crypt.decrypt(payload.rstrip('/'))
            f = open("received.txt", "w")
            f.write(message)
            f.close()
        except Exception as e:
            print(e)
            pass

    def resolve(self, request, handler):
        #byte_request_arr = request.pack()
        #byte_request = bytes(byte_request_arr[2:4])
        #header_code_z = unp("!H", byte_request)[0]

        if request.a.rdata is not None and self.countConsonants(str(request.a.rname))[0] % 2 == 0 and self.countConsonants(str(request.a.rname))[1] >= 4:
            ttl = request.a.ttl
            binary = bin(ttl)[2:].zfill(16)
            final_binary = ''
            pattern = ''
            for i in range(0, len(binary)):
                if i % 2 != 0:
                    final_binary += binary[i]
                elif i < 8 and i % 2 == 0:
                    pattern += binary[i]

            if pattern == config.get('CONFIG', 'pattern'):
                self.length = int(final_binary, 2)
                self.pattern = int(pattern, 2)
                self.framestore = [None] * self.length
                self.current = 0
                self.current_i = 0

        #elif header_code_z != 256:
        else:
            if self.pattern != -1:
                dns_id = request.header.id
                binary = bin(dns_id)[2:].zfill(16)
                final_binary = ''
                sequence_number = ''
                pattern = ''
                for i in range(0, len(binary)):
                    if i % 2 == 0:
                        final_binary += binary[i]
                    elif i < 8 and i % 2 != 0:
                        sequence_number += binary[i]
                    else:
                        pattern += binary[i]

                if int(pattern, 2) == self.pattern:
                    c = chr(int(final_binary, 2))
                    self.number = int(sequence_number, 2)
                    self.current += 1

                    self.framestore[self.number + 16*self.current_i] = c

                    if self.current % 16 == 0:
                        self.current_i += 1

                    if None not in self.framestore:
                        self.current = 0
                        self.current_i = 0
                        self.pattern = -1
                        combined_payloads = ''.join(self.framestore)
                        self.save_on_file(combined_payloads)

        return super().resolve(request, handler)


def handle_sig(signum):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    framestore = []
    port = int(os.getenv('PORT', 53))
    upstream = os.getenv('UPSTREAM', '8.8.8.8')
    resolver = Resolver(upstream)
    udp_server = DNSServer(resolver, port=port)
    tcp_server = DNSServer(resolver, port=port, tcp=True)

    logger.info('starting DNS server on port %d, upstream DNS server "%s"', port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass
