# Pcaphunt
Python program to analyze and discover possible threats in a pcap file
# Supported threats
- arp spoofing
- ping of death
- icmp flood
- syn flood
- dns request flood
- unexpected packets loss
- vlan hopping
# How to run
In order to run this program you must have python 3.x and pip3 installed.

The prerequisites to run this program are wireshark, tshark and the python modules nest_asyncio and pyshark:

- `sudo apt update`
- `sudo apt upgrade -y`
- `sudo apt install wireshark`
- `sudo apt install tshark`
- `pip3 install nest_asyncio`
- `pip3 install pyshark`

Clone the repositoty:
- `git clone https://github.com/markfvl/Pcaphunt.git`

To run the program:
- `python3 pcaphunt.py <filepcap>`
  
**Note**: pcaps with annotations or comments could break the application.
