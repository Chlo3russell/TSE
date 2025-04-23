import time
import logging
import subprocess
import os

## Class for blocking & unblocking IPs using iptables
class Blocker:
    def __init__(self, block_duration):
        self.block_duration = block_duration # Duration the IPs will be blocked for in seconds
        self.blocked_ips = {} # Dictionary to track blocked IPs & expiry times

    def _run_command(self, *args):
        '''
        Helper function to run given commands

        Args:
            *args: Inputs to be merged into a list
        '''
        if os.name == "posix":
            command = ['iptables'] + list(args)
            print(f"Executing command: {' '.join(command)}") # Debugging statement
            subprocess.run(command, check= True)
        elif os.name == "nt":
            command = ['netsh'] + list(args)
            print(f"Executing command: {' '.join(command)}") # Debugging statement
            subprocess.run(command, check= True)

    def block_ip(self, ip_address):
        '''
        Blocks a given IP Address using the users corresponding OS command

        Args:
            ip_address: IP Address to block
        '''
        if ip_address not in self.blocked_ips:
            if os.name == "posix":
                self._run_command("-A", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT) matching packets to the source ip address given, (-j DROP) block that traffic.
            elif os.name == "nt":
                # Apply the rule to each profile explicitly
                for profile in ["DOMAIN", "PRIVATE", "PUBLIC"]:
                    command = ["advfirewall", "firewall", "add", "rule", f"name=\"Block {ip_address} {profile}\"", "dir=in", "action=block", f"remoteip={ip_address}", f"profile={profile}", "enable=yes"]
                    print(f"Executing command: {' '.join(command)}")
                    subprocess.run(command, check=True)
            self.blocked_ips[ip_address] = time.time() + self.block_duration # When does that IP block last till
    
    def unblock_ip(self, ip_address):
        '''
        Unblocks a given IP Address using the users corresponding OS command

        Args:
            ip_address: IP Address to unblock
        '''
        if ip_address in self.blocked_ips:
                if os.name == "posix":
                    self._run_command("-D", "INPUT", "-s", ip_address, "-j", "DROP") # Command to change the firewall rules (iptables), delete a rule (-D) for the incoming traffic (INPUT), get the blocked source ip (-s ip_address) and remove that rule/ the block (-j DROP)
                elif os.name == "nt":
                    self._run_command("advfirewall", "firewall", "delete", "rule", f"name=\"Block {ip_address}\"")
                del self.blocked_ips[ip_address]

    ### TODO: This may be redundant depending on how the database has been handled.
    def unblock_list(self):
        '''
        Unblocks all IP Addresses where their block time has expired
        '''
        for ip_address, block_time in list(self.blocked_ips.items()):
            if time.time() >= block_time:
                self.unblock_ip(ip_address)

    def get_blocked_ips(self):
        '''
        Gets a list of the blocked IPs from the users firewall

        Returns:
            list: Currently Blocked IPs
        '''
        if os.name == "posix":
            command = subprocess.check_output(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Command to change the firewall rules (iptables), list all rules (-L) for the incoming traffic (INPUT), display IPs (-n), show rule numbers (--line-numbers) which is useful for deleting rules by number is multiple rle were on one IP
            return [line.split()[3] for line in command.stdout.splitlines() if "DROP" in line]
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

    def check_firewall_rules(self):
        '''
        Gets the firewall rules from the users OS firewall service

        Returns:
            string: Firewall rules
        '''
        if os.name == "posix":
            command = subprocess.check_output(["iptables", "-L", "-n", "--line-numbers"], capture_output=True, check=True, text=True) # Same command in the get_self.blocked_ips function but runs it in shell and returns the output
        elif os.name == "nt":
            command = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], capture_output= True, check=True, text=True)
        return command.stdout  

    def add_rate_limit(self, protocol, port=None, per_second = 25, burst_limit = 50):
        '''
        Adds the rate limit based on user's or default inputs

        Args:
            protocol: Protocol the limit applies to
            port: Port the limit applies to
            per_second: Packets that a connection is permitted to transmit per second
            burst_limit: Packets in a burst that are allowed to transmit before limits are applied
        '''
        if port:
            self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT")
            self._run_command("-A", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP")
        else:
            self._run_command("-A", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") # Command to change the firewall rules (iptables), append the rule (-A) to the incoming traffic (INPUT), (-p tcp) apply to tcp packets, (--syn) target syn packets, (-m limit) use limit module for rate limiting, (--limit ) allow a certain amount of packets per second - default 25, (-- limit- burst ) allow a burst of 50 packets before enforcing the rule, (-j ACCEPT) now accept traffic that was once blocked. 
            self._run_command("-A", "INPUT", "-p", protocol, "-j", "DROP") # Blocks excess syn packets beyond this point

    def remove_rate_limit(self, protocol, port= None, per_second = 25, burst_limit = 50):
        '''
        Removes the rate limit based on user's or default inputs

        Args:
            protocol: Protocol the limit applies to
            port: Port the limit applies to
            per_second: Packets that a connection is permitted to transmit per second
            burst_limit: Packets in a burst that are allowed to transmit before limits are applied
        '''
        if port: 
            self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP")
            self._run_command("-D", "INPUT", "-p", protocol, "--dport", str(port), "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT")
        else:
            self._run_command("-D", "INPUT", "-p", protocol, "-j", "DROP") # Drops the block 
            self._run_command("-D", "INPUT", "-p", protocol, "-m", "limit", "--limit", f"{per_second}/s", "--limit-burst", f"{burst_limit}", "-j", "ACCEPT") # Command to change the firewall rules (iptables), delete the rule (-D) to the incoming traffic (INPUT).