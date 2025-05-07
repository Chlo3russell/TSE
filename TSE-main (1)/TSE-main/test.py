from defense.defenseScript import Blocker
import time
from firewallMonitor import Firewall

blocker = Blocker()
firewall = Firewall()
'''
blocker.block_ip("192.168.10.30")
time.sleep(5)
blocker.block_ip("192.168.10.30")
time.sleep(5)
print(blocker.get_blocked_ips())
time.sleep(5)
#blocker.check_firewall_rules()
time.sleep(5)
blocker.unblock_ip("192.168.10.30")
time.sleep(5)
blocker.unblock_ip("192.168.10.30")
time.sleep(5)
print(blocker.get_blocked_ips())

#print(blocker.check_firewall_rules())
while blocker.check_if_ip_blocked('192.168.0.80') == True:
    blocker.get_blocked_ips()
    blocker.unblock_ip("192.168.0.80")
'''
firewall.block_ip('192.168.60.6')