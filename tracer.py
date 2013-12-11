#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# Scapy Library Required
from scapy.all import *
import socket as s
import argparse
from random import randint
from sys import argv
###############USAGE########################
usage='''Usage: %s [OPTIONS] HOST
           
  OPTIONS:
  -P PROTO            Protocol Type (tcp/udp/icmp)
  -s SPORT            Local Port
  -p PORT             Remote Port
  -T TTL              Time To Live
  -t TIMEOUT          Timeout
  -v 		              Version
  TCP:
    -f FLAG           TCP Flag
        syn -->  syn trace
	      ack -->  ack trace
	      fin -->  fin trace
	      sack --> syn+ack trace
	      rst -->  rst trace
	      urg -->  urg trace
	      fpu -->  xmas trace
  ICMP:
    -R REQ            ICMP Request Type
        echo-reply (0)
        echo-request (8)
        timestamp (13)
Target Specs:
  HOST              Remote Host''' % argv[0]
###################Args#####################
parser = argparse.ArgumentParser(usage=usage)
parser.add_argument('-P', 
		                dest='protocol')
parser.add_argument('-s', 
		                dest='sport')
parser.add_argument(type=str,
                    dest='rhost')
parser.add_argument('-p', 
		                dest='rport', 
		                default='80')
parser.add_argument('-f', 
		                dest='flag', 
		                default='S')
parser.add_argument('-T', 
		                dest='ttl', 
		                default='10')
parser.add_argument('-t', 
		                dest='timeout', 
		                default='3')
parser.add_argument('-v', 
		                action='version', 
		                version='tracer v1.0 (Coded By Mahy)')
parser.add_argument('-R', 
		                dest='icmpreq',
		                type=str,
		                default='echo-request')
args = parser.parse_args()
protocol = args.protocol
sport = args.sport
rhost = args.rhost
rport = args.rport
flag = args.flag
ttl = args.ttl
timeout = args.timeout
icmpreq = args.icmpreq
#################Trace-Tools################
def tcptracer():
  ip = IP()
  tcp = TCP()
  ip.dst = rhost
  ip.ttl = list(range(1,int(ttl)))
  if(sport == "any" or sport == "ANY"):
    tcp.sport = RandShort()
  else:
    tcp.sport=int(sport)
  if(rport == "any" or rport == "ANY"):
    tcp.dport = RandShort()
  else:
    tcp.dport = int(rport)
  if(flag == "syn" or flag == "SYN"): # Syn Trace
    tcp.flags="S"
  elif(flag == "ack" or flag == "ACK"): # Ack Trace
    tcp.flag="A"
  elif(flag == "sack" or flag == "SACK"): # Syn-Ack Trace
    tcp.flag="SA"
  elif(flag == "fin" or flag == "FIN"): # Fin Trace
    tcp.flag="F"
  elif(flag == "rst" or flag == "RST"): # Rst Trace
    tcp.flag="R"
  elif(flag == "urg" or flag == "URG"): # Urg Trace
    tcp.flag="U"
  elif(flag == "fpu" or flag == "FPU"): # Xmas Trace
    tcp.flag="FPU"
  else:
    print "Invalid Tcp Flag"
    exit(1)
  protocols = ip/tcp
  ans,unans=sr(protocols,verbose=0, timeout=int(timeout))
  print("HOST\t\t\tTTL\t\tREQUEST\t\tRESPONSE")
  ans.summary(lambda(s,r):
		r.sprintf("%IP.src%\t\t%IP.ttl%\t\t"+str(flag).upper()+"\t\t{TCP:%TCP.flags%}"))

def udptracer():
  ip = IP()
  udp = UDP()
  ip.dst = rhost
  ip.ttl = list(range(1,int(ttl)))
  if(sport == "any" or sport == "ANY"):
    udp.sport = RandShort()
  else:
    udp.sport = int(sport)
  if(rport == "any" or rport == "ANY"):
    udp.dport = RandShort()
  else:
    udp.dport = int(rport)
  protocols = ip/udp
  ans,unans=sr(protocols,verbose=0, timeout=int(timeout))
  print("HOST\t\t\tTTL")
  ans.summary(lambda(s,r):
		r.sprintf("%IP.src%\t\t%IP.ttl%"))

def icmptracer():
  ip = IP()
  icmp = ICMP()
  ip.dst = rhost
  ip.ttl = list(range(1,int(ttl)))
  icmptypes = {"echo-reply" : 0,"echo-request" : 8,"timestamp" : 13}
  for t in icmptypes.keys():
    if t == icmpreq:
      icmp.type = t
    else:
      pass
  protocols = ip/icmp
  ans,unans=sr(protocols, verbose=0, timeout=int(timeout))
  print("HOST\t\t\tTTL\t\tRESPONSE")
  ans.summary(lambda(s,r):r.sprintf("%IP.src%\t\t%IP.ttl%\t\t%ICMP.type%"))
###################Running#####################
if(str(protocol) == "tcp" or str(protocol) == "TCP"):
  tcptracer()
elif(str(protocol) == "udp" or str(protocol) == "UDP"):
  udptracer()
elif(str(protocol) == "icmp" or str(protocol) == "ICMP"):
  icmptracer()
