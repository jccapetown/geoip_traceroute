#!/usr/bin/python
#Author:			Jacques Coetzee
#Description: Show Ip Location of tracert.
from scapy.all import *
import os,sys

import IP2Location;


def tracert(ip):
	hostname = ip
	for i in range(1, 28):
			pkt = IP(dst=hostname, ttl=i) / UDP(dport=80)
			# Send the packet and get a reply
			reply = sr1(pkt, verbose=0, timeout=5)
			if reply is None:
					# No reply =(
					print "%d hops away: " % i , "* Blocked or Filtered by hop ", (i-1)
					break
			elif reply.type == 3:
					# We've reached our destination
					print "Done!", reply.src
					break
			else:
					# We're in the middle somewhere
					_short,_long = get_location(reply.src)
					print "%d hops away: " % i , reply.src, _long


def get_location(ip):
	IP2LocObj = IP2Location.IP2Location();
	IP2LocObj.open("data/IP-COUNTRY.BIN");
	rec = IP2LocObj.get_all(ip);

	#print rec.country_short
	#print rec.country_long
	return (rec.country_short, rec.country_long)

header = '''
Geotrace
Author: Jacques Coetzee @ 2105
Description: Traceroute with geolocation lookup

'''

usage= '''
usage: geotrace <ip>

'''

os.system('clear')
if len(sys.argv) == 1:
	print header
	print usage
	sys.exit()

target = sys.argv[1]

print header
tracert(target)
#ans,unans=sr(IP(dst=target,ttl=30,id=RandShort())/TCP(flags=0x2),timeout=5,	verbose=True)
#for snd,rcv in ans:
#	print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)

#print unans[IP]
#or snd,rcv in unans:
#print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)

