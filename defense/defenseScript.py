'''
Script not meant to be ran on it's own, use defenseMonitor.
'''
import time
import logging
import subprocess
import os

## Logging config - better for traceability & debugging instead of print
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

## Class for blocking & unblocking IPs using iptables
class Blocker:
    def __init__(self, block_duration):
        self.block_duration = block_duration # Duration the IPs will be blocked for in seconds
        self.blocked_ips = {} # Dictionary to track blocked IPs & expiry times

    def _run_command(self, *args):
        try:
            if os.name == "posix":
                subprocess.run(['iptables'] + list(args), check= True)
            elif os.name == "nt":
                subprocess.run(['netsh'] + list(args), check= True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Unable to run iptables command | {e}")
            raise

    def block_ip(self, ip_address):
        ## Blocks IPs using iptables
        try:
            if ip_address not in self.blocked_ips:
                if os.name == "posix":
                    self._run_command("-A", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT) matching packets to the source ip address given, (-j DROP) block that traffic.
                elif os.name == "nt":
                    self._run_command("advfirewall", "firewall", "add", "rule", f"name=\"Block {ip_address}\"", "dir=in", "action=block", f"remoteip={ip_address}", "enable=yes")
                self.blocked_ips[ip_address] = time.time() + self.block_duration # When does that IP block last till
                logging.info(f"Blocked IP Address {ip_address}")
            else:
                logging.warning(f"IP Address {ip_address} is already blocked")
        except Exception as e:
            logging.error(f"Unable to block IP Address {ip_address} | {e}")

    def unblock_list(self):
        ## Clean the blocked_ips table
        try:
            for ip_address, block_time in list(self.blocked_ips.items()):
                if time.time() >= block_time:
                    if os.name == "posix":
                        self._run_command("-D", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), delete a rule (-D) for the incoming traffic (INPUT), get the blocked source ip (-s ip_address) and remove that rule/ the block (-j DROP)
                    elif os.name == "nt":
                        self._run_command("advfirewall", "firewall", "delete", "rule", f"name=\"Block {ip_address}\"")
                    del self.blocked_ips[ip_address]
                    logging.info(f"Unblocked IP Address {ip_address}")
        except Exception as e:
            logging.error(f"Unable to unblock IPs | {e}")

    def manual_unblock(self, ip_address):
        ## Manually unblock a specific ip
        try:
            if ip_address in self.blocked_ips:
                if os.name == "posix":
                    self._run_command("-D", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), delete a rule (-D) for the incoming traffic (INPUT), get the blocked source ip (-s ip_address) and remove that rule/ the block (-j DROP)
                elif os.name == "nt":
                    self._run_command("advfirewall", "firewall", "delete", "rule", f"name=\"Block {ip_address}\"")
                del self.blocked_ips[ip_address]
                logging.info(f"Manually blocked IP Address {ip_address}")
            else:
                logging.warning(f"IP Address {ip_address} isn't in current list of blocked IPs")
        except Exception as e:
            logging.error(f"Unable to unblock IP Address {ip_address} | {e}")

    def get_blocked_ips(self):
        ## Retrieve the list of blocked ips from iptables to check which ones are blocked
        try:
            if os.name == "posix":
                command = subprocess.check_output(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Command to change the firewall rules (iptables), list all rules (-L) for the incoming traffic (INPUT), display IPs (-n), show rule numbers (--line-numbers) which is useful for deleting rules by number is multiple rle were on one IP
                blocked = [line.split()[3] for line in command.stdout.splitlines() if "DROP" in line]
                return blocked
            elif os.name == "nt":
                command = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], capture_output= True, check= True, text= True)
                blocked = []
                current_rule = {}

                for line in command.stdout.splitlines():
                    if "Rule Name:" in line:
                        if current_rule.get("action") == "Block" and current_rule.get("remoteip"):
                            blocked.extend(current_rule["remoteip"].split(','))
                        current_rule = {"name": line.split(":")[1].strip()}
                    elif "Action:" in line:
                        current_rule["action"] = line.split(":")[1].strip()
                    elif "RemoteIP" in line:
                        current_rule['remoteip'] = line.split(":")[1].strip()
                
                if current_rule.get("action") == "Block" and current_rule.get("remoteip"):
                    blocked.extend(current_rule["remoteip"].split(','))
                return line(set(blocked))

        except subprocess.CalledProcessError as e:
            logging.error(f"Unable to retrieve blocked IPs | {e}")
            return []

    def check_table_rules(self):
        ## Returns/ Prints the current rules of the IP table
        try:
            if os.name == "posix":
                command = subprocess.check_output(["iptables", "-L", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Same command in the get_self.blocked_ips function but runs it in shell and returns the output
                logging.info("Current iptables rules:\n", command.stdout)
            elif os.name == "nt":
                command = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], capture_output= True, check=True, text=True)
                logging.info("Current firewall rules:\n" + command.stdout)
        except subprocess.CalledProcessError as e:
            logging.error(f"Unable to retrieve rules | {e}")

    def add_rate_limit(self, protocol, port=None, per_second = 25, burst_limit = 50):
        ## Add iptables rule to limit syn packets directly
        try:
            if port:
                self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT")
                self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP")
            else:
                self._run_command("-A", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT), (-p tcp) apply to tcp packets, (--syn) target syn packets, (-m limit) use limit module for rate limiting, (--limit ) allow a certain amount of packets per second - default 25, (-- limit- burst ) allow a burst of 50 packets before enforcing the rule, (-j ACCEPT) now accept traffic that was once blocked. 
                self._run_command("-A", "INPUT", "-p", protocol, "-j", "DROP") # Blocks excess syn packets beyond this point
            logging.info(f"Rate limiting applied for {protocol} (port {port}): {per_second}/s with burst limit {burst_limit}")
        except Exception as e:
            logging.error(f"Unable to apply rate limiting | {e}")

    def remove_rate_limit(self, protocol, port= None, per_second = 25, burst_limit = 50):
        ## Remove iptables rules (assuming there is only one rate limiting rule currently - can be adapted for more)
        try:
            if port: 
                self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP")
                self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT")
            else:
                self._run_command("-D", "INPUT", "-p", protocol, "-j", "DROP") # Drops the block 
                self._run_command("-D", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") # Command to change the firewall rules (iptables), delete the rule (-D) to the incoming traffic (INPUT). 
            logging.info(f"Rate limiting removed for {protocol} (port {port}): {per_second}/s with burst limit {burst_limit}")
        except Exception as e:
            logging.error(f"Unable to remove rate limit | {e}")