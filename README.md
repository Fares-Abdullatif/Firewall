# Python Firewall

A lightweight Python-based firewall application that monitors and controls network traffic on specified interfaces. Built using Scapy, this firewall allows you to blacklist IPs, manage allowed/blocked ports, and control ICMP traffic with an easy-to-use command-line interface.

## Features

- **IP Blacklisting**: Add or remove IP addresses to/from a blacklist
- **Port Management**: Set allowed and blocked ports for TCP/UDP traffic
- **ICMP Control**: Allow or block ICMP (ping) traffic
- **Traffic Logging**: Monitor and log all network events
- **Real-time Monitoring**: Sniff and process packets on specified network interfaces
- **CLI Interface**: User-friendly command-line interface for easy configuration

## Requirements

- Python 3.x
- Scapy (`pip install scapy`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Fares-Abdullatif/Firewall.git
cd Firewall
```

2. Install required dependencies:
```bash
pip install scapy
```

## Usage

### Basic Commands

Start firewall on a specific network interface:
```bash
python firewall.py --interface Ethernet
```

### IP Blacklisting

Add an IP to the blacklist:
```bash
python firewall.py --blacklist 192.168.1.100
```

Remove an IP from the blacklist:
```bash
python firewall.py --unblacklist 192.168.1.100
```

### Port Management

Set allowed ports (only these ports will be allowed):
```bash
python firewall.py --allow-ports 80 443 22
```

Set blocked ports (these ports will be blocked):
```bash
python firewall.py --block-ports 25 135 139
```

### ICMP Control

Allow ICMP traffic (ping):
```bash
python firewall.py --allow-icmp
```

Block ICMP traffic:
```bash
python firewall.py --block-icmp
```

### View Traffic Logs

Display all traffic logs:
```bash
python firewall.py --show-logs
```

## How It Works

### Core Components

- **Packet Callback**: Processes each intercepted packet and applies filtering rules
- **Blacklist Filtering**: Drops packets from blacklisted IP addresses
- **Port Filtering**: Enforces allowed/blocked port policies for TCP/UDP traffic
- **ICMP Handling**: Allows or blocks ICMP packets based on configuration
- **Logging System**: Records all events to both file and console

### Packet Processing Flow

1. Capture incoming packets using Scapy's packet sniffer
2. Check if source IP is blacklisted → Drop if blacklisted
3. Check for ICMP traffic → Apply ICMP policy
4. Check for TCP/UDP traffic → Apply port policies
5. Log the result (allowed/blocked) and action taken

### Configuration Variables

Edit the global variables in `firewall.py` to customize default behavior:

```python
BLACKLISTED_IPS = set()      # IPs to block
ALLOWED_PORTS = set()         # Only allow these ports (empty = allow all)
BLOCKED_PORTS = set()         # Ports to block
ALLOW_ICMP = True             # Allow ICMP by default
```

## Logs

All traffic events are logged to `firewall.log` with timestamps. The log file maintains a persistent record of:
- Allowed packets
- Blocked packets (with reason)
- Configuration changes

## Important Notes

⚠️ **Administrative Privileges Required**: Running this firewall requires administrative/root privileges on most systems.

⚠️ **Network Interface**: Specify your correct network interface name (e.g., `Ethernet`, `Wi-Fi`, `eth0`, `en0`).

⚠️ **Testing Environment**: Test in a controlled environment before using in production.

## Example Usage Scenarios

### Scenario 1: Block all traffic from a specific IP
```bash
python firewall.py --blacklist 192.168.1.50
python firewall.py --interface Ethernet
```

### Scenario 2: Only allow web traffic (HTTP/HTTPS)
```bash
python firewall.py --allow-ports 80 443
python firewall.py --interface Ethernet
```

### Scenario 3: Block common attack ports
```bash
python firewall.py --block-ports 25 135 139 445
python firewall.py --interface Ethernet
```

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Feel free to fork the repository and submit pull requests for improvements or bug fixes.

## Support

For issues or questions, please open an issue on the GitHub repository.
