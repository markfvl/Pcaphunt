import sys
import os
import pyshark 

from net.attacks.networkattacks import *
from utils.parser import *
from utils.pcapStat import *

####################################################

if __name__ == "__main__":

    #taking the pcap path
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        filePath = sys.argv[1]
    else:
        filePath = inputFilePath()
        
    print("ANALYSING the pcap...\n")
    cap = pyshark.FileCapture(filePath)
    stats = basicStat(cap)

    arpSpoofing(filePath)
    packet_loss(filePath, stats['tcp_packets'])
    pingOfDeathIPv4(filePath)
    icmpFlood(filePath)
    syn_flood(filePath)
    dns_req_flood(filePath, stats['total_packets'])

    #STATS 
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\nGeneral stats:")
    for key, value in stats.items():
        if(key == 'total_packets'):
            print(f"\t{key} : {value}")
        elif(value != 0):
            print(f"\t{key} : {value}\t({value*100/stats['total_packets']}%)")
    print()
