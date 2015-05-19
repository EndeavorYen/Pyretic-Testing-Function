#############################################
#                                           #
#            Source NAT Module              #
#                                           #
#          Demo version by Simon            #
#                                           #
#                 ver 2.0                   #
#                                           #
#############################################
"""

ver.2 : 

Progressing...

"""


from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

client_IP = IPAddr('10.0.0.1')
public_IP = IPAddr('140.120.15.178')
client_MAC = EthAddr('40:61:86:c8:6b:f1')
public_MAC = EthAddr('40:61:86:c8:6b:f3')
gateway_MAC = EthAddr('00:1f:c9:61:90:c7')
ICMP_PROTO = 0x01
TCP_PROTO = 0x06
UDP_PROTO = 0x11
ARP_TYPE = 0x0806
IP_TYPE = 0x0800

class SNAT(DynamicPolicy):

    def __init__(self):
        super(SNAT,self).__init__()
        self.flood = flood() + fwd(65534)    
        self.set_initial_state()

    def set_initial_state(self):
        self.modify = identity
        self.modify2 = identity
        self.Q_MAC = packets(1,['srcmac'])
        self.Q_MAC.register_callback(self.learn_new_MAC)
        self.Q_Port = packets(1, ['srcport'])
        self.Q_Port.register_callback(self.learn_new_Port)
        self.forward = self.flood 
        self.NAT_Rule()
        self.update_policy()

    def set_network(self,network):
        self.set_initial_state()

    def learn_new_MAC(self,pkt):
        self.forward = if_(match(dstmac=pkt['srcmac']), fwd(pkt['inport']), self.forward) 
        self.update_policy()

    def learn_new_Port(self, pkt):
        self.Port_cond = match(ethtype = IP_TYPE) &  (match(protocol = TCP_PROTO) | match(protocol = UDP_PROTO)) & match(dstport = pkt['srcport'])
                
        if (pkt['srcip'] == client_IP) :
           self.modify2 = if_(self.Port_cond, modify(dstip = pkt['srcip'], dstmac = pkt['srcmac']), self.modify2)

    def NAT_Rule(self):
        self.OUT_cond =  match(srcip = client_IP) & ~match(dstip = public_IP)   # OUT
        self.ICMP_cond = match(ethtype = IP_TYPE, protocol = ICMP_PROTO) & ~match(srcip = client_IP) & match(dstip = public_IP)  # IN - Only NAT ICMP

        self.modify = (if_(self.OUT_cond, modify(srcip = public_IP, srcmac = public_MAC, dstmac = gateway_MAC)) >>
                     if_(self.ICMP_cond, modify(dstmac = client_MAC, dstip = client_IP), self.modify))

    def update_policy(self):
        self.policy_cond = match(ethtype = IP_TYPE) >>  (match(protocol = TCP_PROTO) + match(protocol = UDP_PROTO))
  
        self.policy = (self.modify2 >> self.modify >> self.forward) + (self.Q_MAC + (self.policy_cond >> self.Q_Port))
        #self.policy = ((self.modify >> self.modify2) >> self.forward) + self.Q_MAC + self.Q_Port
        print self.policy

               

def main():
    return SNAT()
