import pcapy
import sys

reader = pcapy.open_offline(sys.argv[1])
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
