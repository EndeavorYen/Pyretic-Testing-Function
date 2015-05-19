###########################################
#                                         #
#                                         #
#           Traffic Detector              #
#                ver.1                    #
#               by Simon                  #
#                                         #
#                                         #
###########################################

from pox.core import core
import pox.openflow.libopenflow_01 as of
#from pox.lib.util import dpid_to_str
#from pox.lib.util import str_to_bool
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner_EX import mac_learner

# -----------------------------------------------------------------------

src = "match: ('srcip', 10.0.0.1) ('dstip', 10.0.0.2)"
interval = 60                                     # interval = 60 seconds
queue = [0 for i in range(0, interval)]
i = 0
total = 0
prev = 0
target = ""
tag = 0

# -----------------------------------------------------------------------

condition = if_(match(srcip = IPAddr('10.0.0.1'), dstip = IPAddr('10.0.0.2')), drop)
forward = identity

def main():
	return (byte_counts() + (mac_learner() >> forward))

def byte_counts():
	q = count_bytes(1,['srcip','dstip'])
	q.register_callback(traffic_count)
	return q

def traffic_count(n):
	global target, prev, queue, total, interval, i, forward, condition, tag, openflow
	
	if cmp(str(target), src) != 0:    # target != src 
		find_src(n)
	else : 
		diff  = n[target] - prev
		prev = n[target]
		queue[i] = diff
		total = total + queue[i] - queue[(i + 1) % interval]
		i = (i + 1) % interval
		print "\n-----------------------------------------\n"
		print "h1 to h2 traffic per sec    >>> ", diff / 1024, "KB/s"
		print "h1 to h2 traffic per minute >>> ", total / (1024),"KB/min "
		#print forward

		if (total / 1024) >= 1 and tag == 0 :   # traffic >= 10 MB/min
			print "==============================="
			print "Traffic Over 10MB per minute ! "
			print "==============================="
			print "msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)"
			print "connection.send(msg)"
			print "Update flow table"
			msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
			for connection in core.openflow.connections :
				connection.send(msg)
			forward = condition
			#print forward
			tag = 1
		#elif (diff / 1024) >= 350 :   # traffic >= 350 KB/s
		#	print "XOXOXOXOXOXOXOXOXOXOXO"
		#	forward = condition
		elif tag == 1 :
			print "Cut h1-->h2 Network"
			print "Cut h1-->h2 Network"
			print "Cut h1-->h2 Network"
		
def find_src(n) :
	global target
	for i in n : 
		if cmp(str(i),  src) == 0 :
			target = i
