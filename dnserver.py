import logging
import os
import signal
from datetime import datetime
from time import sleep
from struct import unpack as unp

from dnslib import QTYPE, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

from crypt import Crypt

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
        self.end = False

    def resolve(self, request, handler):
        byte_request_arr = request.pack()
        byte_request = bytes(byte_request_arr[2:4])
        header_code_z = unp("!H", byte_request)[0]

        if request.a.rdata is not None:
            for x in range(32, 126):
                for y in range(32, 126):
                    res = (x * 256 + y) * 2
                    if int(res) == int(request.a.ttl):
                        self.framestore.append(chr(x) + chr(y))
                        if chr(x) == '/' and chr(y) == '/':
                            self.end = True
                        break

            if self.end:
                combined_payloads = ''.join(self.framestore)

                self.end = False
                self.framestore = []

                try:
                    message = Crypt.decrypt(combined_payloads.rstrip('/'))
                    f = open("received.txt", "w")
                    f.write(message)
                    f.close()
                except Exception as e:
                    print(e)
                    pass

        elif header_code_z != 256:
            dns_id = request.header.id
            binary = bin(dns_id)[2:].zfill(16)
            c = chr(int(binary[8:], 2))
            self.framestore.append(c)

            try:
                if len(self.framestore) > 0:
                    if self.framestore[-1] == '/' and self.framestore[-2] == '/':
                        self.end = True

                    if self.end:
                        combined_payloads = ''.join(self.framestore)

                        self.end = False
                        self.framestore = []

                        try:
                            message = Crypt.decrypt(combined_payloads.rstrip('/'))
                            f = open("received.txt", "w")
                            f.write(message)
                            f.close()
                        except Exception as e:
                            self.framestore = []
                            print(e)
                            pass
            except Exception as e:
                self.framestore = []
                print(e)
                pass

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
