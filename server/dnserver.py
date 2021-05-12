import logging
import re
import os
import signal
from datetime import datetime
from time import sleep

from configparser import ConfigParser
config = ConfigParser()
config.read('../configuration.ini')

import importlib.machinery
loader = importlib.machinery.SourceFileLoader('crypt', config.get('CONFIG', 'absolute_path') + 'crypt/crypt.py')
handle = loader.load_module('crypt')

global_func = importlib.machinery.SourceFileLoader('global', config.get('CONFIG', 'absolute_path') + 'global/global.py')
handle_glob = global_func.load_module('global')

from dnslib import QTYPE, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

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
        self.allFrames = []

    def save_on_file(self, payload):
        self.framestore = []
        self.allFrames = []

        try:
            print(payload)
            message = handle.decrypt(payload)
            f = open("received.txt", "w")
            f.write(message)
            f.close()
        except Exception as e:
            print(e)
            pass

    def resolve(self, request, handler):
        if request.a.rdata is not None and handle_glob.countConsonantsandVolwes(str(request.a.rname))[0] % 2 == 0 and \
                handle_glob.countConsonantsandVolwes(str(request.a.rname))[1] >= 4:
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
                self.current_i = 0
                self.allFrames.append("no")
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

                c = chr(int(final_binary, 2))
                search = re.compile(r'[A-Za-z0-9+/= ]').search

                if bool(search(c)):
                    if int(pattern, 2) == self.pattern and handle_glob.countConsonantsandVolwes(str(request.q.qname))[0] % 2 == 0 and \
                            handle_glob.countConsonantsandVolwes(str(request.q.qname))[1] >= 4:
                        if self.allFrames[-1] != "ok":
                            self.allFrames.append("ok")
                            self.number = int(sequence_number, 2)

                            try:
                                self.framestore[self.number + 16 * self.current_i] = c
                            except Exception as e:
                                print(e, self.number + 16 * self.current_i)
                                pass

                            if self.number == 15:
                                self.current_i += 1

                            if None not in self.framestore:
                                self.current_i = 0
                                self.pattern = -1
                                combined_payloads = ''.join(self.framestore)
                                self.save_on_file(combined_payloads)
                        else:
                            print("False Positive")
                            self.allFrames.append("no")
                    else:
                        self.allFrames.append("no")
                else:
                    self.allFrames.append("no")

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
