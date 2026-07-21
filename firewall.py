import argparse
import logging
import os

from scapy.all import sniff, IP, TCP, UDP, ICMP

# Global variables
BLACKLISTED_IPS = set()
ALLOWED_PORTS = set()
BLOCKED_PORTS = set()
ALLOW_ICMP = True  # Set to False to block all ICMP traffic
TRAFFIC_LOGS = []

# Logging setup
LOG_FILE = 'firewall.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')


def load_logs():
    """
    Load existing logs from the log file into the TRAFFIC_LOGS list.
    """
    global TRAFFIC_LOGS
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as file:
            TRAFFIC_LOGS = file.readlines()
    else:
        TRAFFIC_LOGS = []


def log_event(message):
    """
    Logs events and appends them to the traffic logs.
    """
    logging.info(message)
    TRAFFIC_LOGS.append(message)
    print(f"LOG: {message}")  # Print logs to the console for debugging


def packet_callback(packet):
    """
    Callback function to process each packet.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check for blacklisted IPs
        if src_ip in BLACKLISTED_IPS:
            log_event(f"Blocked packet from blacklisted IP: {src_ip}")
            return

        # Check for ICMP traffic
        if ICMP in packet:
            if not ALLOW_ICMP:
                log_event(f"Blocked ICMP packet from {src_ip} to {dst_ip}")
                return
            else:
                log_event(f"Allowed ICMP packet from {src_ip} to {dst_ip}")
                return

        # Check for TCP/UDP traffic
        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if port in BLOCKED_PORTS:
                log_event(f"Blocked packet to blocked port: {port}")
                return
            elif ALLOWED_PORTS and port not in ALLOWED_PORTS:
                log_event(f"Blocked packet to non-allowed port: {port}")
                return

        # Log allowed traffic
        log_event(f"Allowed packet from {src_ip} to {dst_ip}")


def start_firewall(interface):
    """
    Starts the firewall and begins sniffing packets.
    """
    print(f"Starting firewall on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False)


def add_blacklisted_ip(ip):
    """
    Adds an IP to the blacklist.
    """
    BLACKLISTED_IPS.add(ip)
    print(f"Added {ip} to blacklist.")


def remove_blacklisted_ip(ip):
    """
    Removes an IP from the blacklist.
    """
    if ip in BLACKLISTED_IPS:
        BLACKLISTED_IPS.remove(ip)
        print(f"Removed {ip} from blacklist.")
    else:
        print(f"{ip} is not in the blacklist.")


def set_allowed_ports(ports):
    """
    Sets the list of allowed ports.
    """
    global ALLOWED_PORTS
    ALLOWED_PORTS = set(ports)
    print(f"Allowed ports set to: {ALLOWED_PORTS}")


def set_blocked_ports(ports):
    """
    Sets the list of blocked ports.
    """
    global BLOCKED_PORTS
    BLOCKED_PORTS = set(ports)
    print(f"Blocked ports set to: {BLOCKED_PORTS}")


def set_allow_icmp(allow):
    """
    Sets whether ICMP traffic is allowed.
    """
    global ALLOW_ICMP
    ALLOW_ICMP = allow
    print(f"ICMP traffic allowed: {ALLOW_ICMP}")


def show_logs():
    """
    Displays the traffic logs.
    """
    load_logs()  # Load logs from the file
    print("\nTraffic Logs:")
    for log in TRAFFIC_LOGS:
        print(log.strip())  # Remove newline characters from log entries


def cli():
    """
    Command-line interface for the firewall.
    """
    parser = argparse.ArgumentParser(description="Python Firewall CLI", epilog="Example usage:\n"
                                                                               "  python firewall.py --interface Ethernet\n"
                                                                               "  python firewall.py --blacklist 192.168.1.100\n"
                                                                               "  python firewall.py --show-logs",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--interface", help="Network interface to monitor (e.g. Ethernet, Wi-Fi)")
    parser.add_argument("--blacklist", help="Add an IP to the blacklist (e.g. 192.168.1.100)")
    parser.add_argument("--unblacklist", help="Remove an IP from the blacklist (e.g. 192.168.1.100)")
    parser.add_argument("--allow-ports", nargs="+", type=int, help="Set allowed ports (e.g. 80, 443)")
    parser.add_argument("--block-ports", nargs="+", type=int, help="Set blocked ports (e.g. 80, 443)")
    parser.add_argument("--allow-icmp", action="store_true", help="Allow ICMP traffic")
    parser.add_argument("--block-icmp", action="store_true", help="Block ICMP traffic")
    parser.add_argument("--show-logs", action="store_true", help="Show traffic logs")
    args = parser.parse_args()

    if args.blacklist:
        add_blacklisted_ip(args.blacklist)
    elif args.unblacklist:
        remove_blacklisted_ip(args.unblacklist)
    elif args.allow_ports:
        set_allowed_ports(args.allow_ports)
    elif args.block_ports:
        set_blocked_ports(args.block_ports)
    elif args.allow_icmp:
        set_allow_icmp(True)
    elif args.block_icmp:
        set_allow_icmp(False)
    elif args.show_logs:
        show_logs()
    elif args.interface:
        start_firewall(args.interface)
    else:
        parser.print_help()  # Show a help message if no valid command is provided


if __name__ == "__main__":
    cli()
