###########################################
#                                         #
#                                         #
#           Traffic Detector              #
#                ver.2                    #
#               by Simon                  #
#                                         #
#                                         #
###########################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner

# ----------------------------------------------------------------------------

src = "match: ('srcip', 10.0.0.1) ('dstip', 10.0.0.2)"
condition = if_(match(srcip = IPAddr('10.0.0.1'), dstip = IPAddr('10.0.0.2')), drop)
interval = 60                                   # interval = 60 seconds
queue = [0 for i in range(0, interval)]
i = 0
total = 0
prev = 0
target = ""
tag = 0

# ----------------------------------------------------------------------------

class traffic(DynamicPolicy) :

	def __init__(self) :
		super(traffic, self).__init__()
		self.set_init_state()
		
	def set_init_state(self) :
		self.forward = identity
		self.byte_counts()
		self.update_policy()
		
	def update_policy(self) :
		self.policy = self.q + self.forward
		print self.policy
		
	def byte_counts(self) :
		self.q = count_bytes(1, ['srcip', 'dstip'])
		self.q.register_callback(self.traffic_count)
		return self.q
		
	def traffic_count(self, n) :
		global target, prev, queue, i, total, interval, condition, tag
		
		if cmp(str(target), src) != 0:    # target != src 
			self.find_src(n)
		else :
			diff  = n[target] - prev
			prev = n[target]
			queue[i] = diff
			total = total + queue[i] - queue[(i + 1) % interval]
			i = (i + 1) % interval
			print "\n-----------------------------------------\n"
			print "h1 to h2 traffic per sec    >>> ", diff / 1024, "KB/s"
			print "h1 to h2 traffic per minute >>> ", total / (1024),"KB/min "

			if (total / 1024) >= 10240 and tag == 0 :   # traffic >= 10 MB/min
				self.forward = condition
				tag = 1
				self.update_policy()
			#elif self.tag == 1 :
			#	print "Cut h1-->h2 Network"
			#	print "Cut h1-->h2 Network"
			#	print "Cut h1-->h2 Network"

	def find_src(self, n) :
		global target
		for i in n :
                	if cmp(str(i),  src) == 0 :
                        	target = i

	
###################################################
	
def main() :
	return (traffic() >> mac_learner())

