import pyshark
import pandas as pd
cap = pyshark.FileCapture("../test_data/captures1_v2/clean/eth2dump-clean-6h_1.pcap")
#print(cap[1].ip.src)
#print(len(cap))
ips = []
pkt = cap[8]
hex_string = pkt.tcp.payload

hex_split = hex_string.split(':')
hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)

human_readable = ''.join(hex_as_chars)
print(pkt.frame_info.protocols.split(':')[-1])

#print(vars(pkt.tcp))
#print(vars(pkt.frame_info))
src_addr = pkt.ip.src
eth_src = pkt.eth.src
time_overall = pkt.frame_info.time_relative
time_delta = pkt.frame_info.time_delta
protocol =  pkt.transport_layer

src_port = pkt[pkt.transport_layer].srcport
dst_port = pkt[pkt.transport_layer].dstport
packet_size = pkt.captured_length
#print(time_delta)
# for pkt in cap:
#     try:
#         protocol =  pkt.transport_layer
#         src_addr = pkt.ip.src
#         src_port = pkt[pkt.transport_layer].srcport
#         dst_port = pkt[pkt.transport_layer].dstport
#         len = pkt.captured_length
#     except AttributeError as e:
#         pass

# unique = list(set(ips))
# print(unique)
#df = pd.DataFrame([ips], columns = ['IPs'])
#print(df['IPs'].unique())
cap.close()