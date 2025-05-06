from defense.defenseScript import Blocker
import time

blocker = Blocker(300)

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