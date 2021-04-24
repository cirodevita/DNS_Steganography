import pcapy

reader = pcapy.open_offline("dns_4_32bytes.pcap")
sum = 0

while True:
    try:
        (header, payload) = reader.next()

        if header is not None:
            sum += header.getlen()
        else:
            break
    except pcapy.PcapError:
        break

print(sum, "bytes")
