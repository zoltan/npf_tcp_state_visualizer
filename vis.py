from scapy.all import *

flags = { 'F': 0x1,
	  'S': 0x2,
	  'R': 0x4,
	  'P': 0x8,
	  'A': 0x10,
	  'U': 0x20,
	  'E': 0x40,
	  'C': 0x80 }

packets = rdpcap("tcptest1.pcap")

streams = {}

def classify(ip, tcp):
	# if it has the SYN flag set but not the ACK flag set, it's a connection try
	# so let's create the stream entry
	if tcp.flags & flags['S'] and not tcp.flags & flags['A']:
		streams[(ip.src, tcp.sport, ip.dst, tcp.dport)] = [('I', ip, tcp)]
		return

	keyA = (ip.src, tcp.sport, ip.dst, tcp.dport) # let's call this 'I' as initiator
	keyB = (ip.dst, tcp.dport, ip.src, tcp.sport) # let's call this 'S' as server

	if keyA in streams:
		streams[keyA].append(('I', ip, tcp))
	elif keyB in streams:
		streams[keyB].append(('S', ip, tcp))

class NPFTCPState():
	def __init__(self):
		self.seqend = 0
		self.ackend = 0
		self.maxwin = 0
		self.init_run = False

	def init(self, tcp):
		self.seqend = tcp.seq;
		self.ackend = tcp.ack;
		self.maxwin = 1;

	def update(self, ip, tcp):
		if not self.init_run:
			self.init(tcp)
			return

	def show(self):
		return '(', self.seqend, ', ', self.ackend, ')'

def process_stream(packets):
	# two parties: I and S
	states = { 'I': NPFTCPState(), 'S': NPFTCPState() }
	for packet in packets:
		states[packet[0]].update(packet[1], packet[2])

for packet in packets:
	if TCP in packet:
		classify(packet[IP], packet[TCP])

print 'Found ', len(streams), ' streams.'
for key, packets in streams.items():
	process_stream(packets)
