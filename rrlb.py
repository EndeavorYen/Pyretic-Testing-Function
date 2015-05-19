#############################################
#                                           #
#        Round Robin Load Balancer          #
#                                           #
#          Demo version by Simon            #
#                                           #
#############################################


from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from pyretic.modules.mac_learner import mac_learner

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
ip4 = IPAddr('10.0.0.4')
ip5 = IPAddr('10.0.0.5')
servers = [ip4, ip5]
public_IP = IPAddr('10.0.0.11')

class rrlb(DynamicPolicy):   

   """ Initailized  """
   def __init__(self):
      super(rrlb,self).__init__()
      self.init_state()

   def init_state(self):
      self.client = 0
      self.Q = packets(1, ['srcip'])
      self.Q.register_callback(self.round_robin)
      self.modify = identity
      self.update_policy()

   """ Round Robin Function  """
   def round_robin(self, pkt):

      """ Setting  match conditions  """
      self.condition1 = match(srcip = pkt['srcip'], dstip = public_IP)
      self.condition2 = match(srcip = servers[0])
      self.condition3 = match(srcip = servers[1])
      
      """ modify packet  """
      self.modify = (if_(self.condition1, modify(dstip = servers[self.client % 2])) >>
                     if_(self.condition2, modify(srcip = public_IP)) >>
                     if_(self.condition3, modify(srcip = public_IP), self.modify)  )
      self.client += 1
      self.update_policy()      

   def update_policy(self):
      self.policy = self.modify + self.Q
      print "------------------------------------------------------------------" 
      print self.policy

route = (
         (match(dstip = ip1) >> fwd(1)) +
         (match(dstip = ip2) >> fwd(2)) +
         (match(dstip = ip3) >> fwd(3)) +
         (match(dstip = ip4) >> fwd(4)) +
         (match(dstip = ip5) >> fwd(5))
        )


def main():
   return rrlb() >> route
