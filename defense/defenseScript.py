import re
import time
import subprocess
import os
from logs.logger import setup_logger

logger = setup_logger(__name__)

## Class for blocking & unblocking IPs using iptables
class Blocker:
    def _run_command(self, *args) -> bool:
        '''
        Helper function to run given commands\n
        Args:
            *args: inputs to be merged into a list
        '''
        try:
            if os.name == "posix":
                command = ['iptables'] + list(args)
            elif os.name == "nt":
                command = ['netsh'] + list(args)
            else:
                logger.error("Attempted to run command for unsupported OS")
                return False
            
            print(f"Executing command: {' '.join(command)}") # Debugging statement
            subprocess.run(command, check= True)
            return True
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute command {' '.join(command)}: {e}")
        except FileNotFoundError:
            logger.error(f"Firewall file not found | {e}")
        except Exception as e:
            logger.exception(f"Unexpected error while executing command {' '.join(command)}: {e}")
        return False

    def block_ip(self, ip_address) -> bool:
        '''
        Blocks a given IP Address using the users corresponding OS command\n
        Args:
            ip_address: IP Address to block
        '''
        if os.name == "posix":
            self._run_command("-A", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT) matching packets to the source ip address given, (-j DROP) block that traffic.
        elif os.name == "nt":
            if not self.check_if_ip_blocked(ip_address):
            # Apply the rule to each profile explicitly
                for profile in ["DOMAIN", "PRIVATE", "PUBLIC"]:
                    self._run_command("advfirewall", "firewall", "add", "rule", f"name=Block {ip_address} {profile}", "dir=in", "action=block", f"remoteip={ip_address}", f"profile={profile}", "enable=yes")
                logger.info(f"Blocker successfully blocked IP: {ip_address}")
                return True
            logger.warning("Cannot block IP that is already blocked")
            return False
        else:
            logger.error("Invalid OS, cannot run command")
            return False
    
    def unblock_ip(self, ip_address) -> bool:
        '''
        Unblocks a given IP Address using the users corresponding OS command\n
        Args:
            ip_address: IP Address to unblock
        '''
        if self.check_if_ip_blocked(ip_address):
            if os.name == "posix":
                self._run_command("-D", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), delete a rule (-D) for the incoming traffic (INPUT), get the blocked source ip (-s ip_address) and remove that rule/ the block (-j DROP)
            elif os.name == "nt":
                for profile in ["DOMAIN", "PRIVATE", "PUBLIC"]:
                    self._run_command("advfirewall", "firewall", "delete", "rule", f"name=Block {ip_address} {profile}")
            logger.info(f"Blocker successfully unblocked IP: {ip_address}")
            return True
        logger.warning(f"Cannot unblock IP: {ip_address} as it isn't blocked")
        return False

    def get_blocked_ips(self):
        '''
        Gets a list of the blocked IPs from the users firewall\n
        Returns:
            list: Currently Blocked IPs
        '''
        try:
            if os.name == "posix":
                command = subprocess.run(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Command to change the firewall rules (iptables), list all rules (-L) for the incoming traffic (INPUT), display IPs (-n), show rule numbers (--line-numbers) which is useful for deleting rules by number is multiple rle were on one IP
                return [line.split()[3] for line in command.stdout.splitlines() if "DROP" in line]
            elif os.name == "nt":
                command = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], capture_output= True, check= True, text= True)
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
                cleaned_ips = [ip.split('/')[0] for ip in blocked]  
                return cleaned_ips
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to retrieve blocked IPs from Firewall: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error whilst fetching blocked IPs: {e}")
        return []
    
    def check_if_ip_blocked(self, ip_address):
        '''
        Checks if an IP is stored within a firewall\n
        Args:
            ip_address: IP address to check\n
        Returns:
            bool: Whether an IP is indeed blocked by the firewall
        '''
        try:
            blocked_ips = self.get_blocked_ips()
            if ip_address in blocked_ips:
                return True
            else:
                return False
        except Exception as e:
            logger.exception(f"Unexpected error whilst checking for IP in blocked IPs: {e}")

    def check_firewall_rules(self):
        '''
        Gets the firewall rules from the users OS firewall service\n
        Returns:
            string: Firewall rules
        '''
        rules = []
        try:
            if os.name == "posix":
                command = subprocess.run(["iptables", "-L", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Same command in the get_self.blocked_ips function but runs it in shell and returns the output
            elif os.name == "nt":
                command = subprocess.check_output("netsh advfirewall firewall show rule name=all", shell=True, text=True)
                rule_names = re.findall(r"Rule Name:\s+(.*)", command)
                for name in rule_names:
                    if "block" in name.lower():
                        rules.append(name.strip())
                return list(set(rules))
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to check firewall rules: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error whilst checking firewall rules: {e}")
        return []

    def add_rate_limit(self, protocol, port=None, per_second = 25, burst_limit = 50) -> bool:
        '''
        Adds the rate limit based on user's or default inputs\n
        Args:
            protocol: Protocol the limit applies to
            port: Port the limit applies to
            per_second: Packets that a connection is permitted to transmit per second
            burst_limit: Packets in a burst that are allowed to transmit before limits are applied
        '''
        if os.name != "posix":
            logger.error("Cannot perform rate limiting via Iptables on non-linux systems")
            return False
        try:
            if port:
                return (self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") and 
                self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"))
            else:
                return (self._run_command("-A", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") and 
                self._run_command("-A", "INPUT", "-p", protocol, "-j", "DROP")) # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT), (-p tcp) apply to tcp packets, (--syn) target syn packets, (-m limit) use limit module for rate limiting, (--limit ) allow a certain amount of packets per second - default 25, (-- limit- burst ) allow a burst of 50 packets before enforcing the rule, (-j ACCEPT) now accept traffic that was once blocked. 
        except Exception as e:
            logger.exception(f"Error adding rate limit: {e}")
            return False

    def remove_rate_limit(self, protocol, port= None, per_second = 25, burst_limit = 50):
        '''
        Removes the rate limit based on user's or default inputs\n
        Args:
            protocol: Protocol the limit applies to
            port: Port the limit applies to
            per_second: Packets that a connection is permitted to transmit per second
            burst_limit: Packets in a burst that are allowed to transmit before limits are applied
        '''
        if os.name != "posix":
            logger.error("Cannot perform rate limiting via Iptables on non-linux systems")
            return False
        try:
            if port: 
                return (self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP") and
                self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT"))
            else:
                return (self._run_command("-D", "INPUT", "-p", protocol, "-j", "DROP") and 
                self._run_command("-D", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT")) # Command to change the firewall rules (iptables), delete the rule (-D) to the incoming traffic (INPUT).
        except Exception as e:
            logger.exception(f"Error removing rate limit: {e}")
            return False
