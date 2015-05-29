#!/usr/bin/python
#Author:			Jacques Coetzee
#Description: Show Ip Location of tracert.
from scapy.all import *
import os,sys
import datetime
import IP2Location;


def tracert(ip):
	hostname = ip

	print 'TTL ', "IP".ljust(18, ' '), "Country".ljust(20, ' '), "RTT"
	print '====', "=".ljust(18, '='), "=".ljust(20, '='), "==="
	for i in range(1, 28):
			pkt = IP(dst=hostname, ttl=i) / UDP(dport=80)
			# Send the packet and get a reply
			timefrom = datetime.datetime.now()
			reply = sr1(pkt, verbose=0, timeout=10)
			resptime = datetime.datetime.now() - timefrom
			resptime = str( int(resptime.total_seconds() * 1000)) + 'ms'
			
 
			if resptime == '0ms' :
				resptime = '<1ms'			

			if reply is None:
					# No reply =(
					print str(i).ljust(4, ' '), "* * * *"
					break
			elif reply.type == 3:
					# We've reached our destination
					print "Done!", reply.src
					break
			else:
					# We're in the middle somewhere
					strttl = str(i).ljust(4, ' ')
					_short,_long = get_location(reply.src)
					print strttl, reply.src.ljust(18, ' '), _long.ljust(20, ' '), resptime


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

