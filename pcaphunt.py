import sys
import os
import argparse
import pyshark
import pathlib
import nest_asyncio
nest_asyncio.apply()
from colorama import init
init()
from colorama import Fore, Back, Style

import net.attacks.networkattacks as na
import net.attacks.ddosdetection as dd
import net.recon.hostdiscovery as hd
import net.recon.portscan as ps
from net.offense import credentialSniff


from utils.parser import *
from utils.pcapStat import *
import utils.menu

####################### CALL ATTACKS ###########################


def callAttacks(filePath, args, attackTOAnalyse):

    attacks = [na.arpSpoofing, na.packet_loss, dd.pingOfDeathIPv4, dd.icmp_flood, 
                dd.tcp_syn_flood, dd.dns_request_flood, na.vlan_hopping]
    if args.scapy > 0:
        from net.recon.hostdiscoveryScapy import arp_scanningScapy
        scans = [arp_scanningScapy, hd.IP_protocol_scan, hd.icmp_ping_sweeps_scan, 
                hd.tcp_syn_ping_sweep, hd.tcp_ack_ping_sweep, hd.udp_ping_scan]
    else:
        scans = [hd.arp_scanning, hd.IP_protocol_scan, hd.icmp_ping_sweeps_scan, 
                hd.tcp_syn_ping_sweep, hd.tcp_ack_ping_sweep, hd.udp_ping_scan]
    if args.portscan > 0:
        scans.append(ps.port_scan)

    if(args.all > 0 or attackTOanalyse[0] == 3):
        print("\nNETWORK ATTACKS: \n")
        allAttacks(attacks, filePath)
        print("RECON: \n")
        allScans(scans, filePath)
    elif(attackTOanalyse[0] == 1):
        if(attackTOanalyse[1] == 1): #Spoof
            if(attackTOanalyse[2] == 1):
                attacks[0](filePath)
        elif(attackTOanalyse[1] == 2): #DDoS
            if(attackTOanalyse[2] == 1):
                attacks[1](filePath)
            elif(attackTOanalyse[2] == 5):
                attacks[5](filePath)
            elif(attackTOanalyse[2] == 6):
                allAttacks(attacks[1:6], filePath)
            else:
                attacks[attackTOanalyse[2]](filePath)
        elif(attackTOanalyse[1] == 3): # Vlan
            if(attackTOanalyse[2] == 1):
                attacks[-1](filePath)
        elif(attackTOanalyse[1] == 4): # All attacks
            allAttacks(attacks, filePath)
    elif(attackTOanalyse[0] == 2): # Recon
        if(attackTOanalyse[1] == 1):
            if attackTOanalyse[2] !=  7:
                scans[attackTOanalyse[2]](filePath)
            else:
                allScans(scans, filePath)
        if(attackTOanalyse[1] == 2):
            if args.portscan > 0:
                scans[-1](filePath)
            else:
                print("Error! Port Scan flag is disabled.\nTry re-run the program with -ps (-h for more info)\n")
                sys.exit(-2)
    else:
        print("Some error has accurred, quitting...")
        sys.exit(-1)
        
# Scans the pcap on all network attacks
def allAttacks(attacks, filePath):
    for a in attacks:
        a(filePath)

# Scans the pcap on all host discovery attacks
def allScans(scans, filePath):
     for s in scans:
            s(filePath)
            
####################### MAIN ########################

if __name__ == "__main__":

    #PARSER
    parser = argparse.ArgumentParser(prog="PcapHunt", description="program to analyze and discover possible threats in a pcap file.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--all", help="Execute all attack scans", action="count", default=0)
    group.add_argument("-O", "--offensive", help="Starts offensive mode (default starts all attacks)", choices=["ftp", "http", "all"], default="none")
    parser.add_argument("filePath", metavar="pcapFile", type=pathlib.Path, help="Path to pcap file to analyze")
    parser.add_argument("-s", "--scapy", help="Use scapy functions", action="count", default=0)
    parser.add_argument("-ps", "--portscan", help="Activate detection of port scans (requires py-radix to be installed)", action="count", default=0)
    parser.add_argument("-v", "--verbose", help="Verbose mode", action="count", default=0)
    args = parser.parse_args()

    #PCAP PATH
    if os.path.isfile(args.filePath):
        filePath = str(args.filePath)
    else:
        filePath = inputFilePath()

    cap = pyshark.FileCapture(filePath)
    attackTOanalyse = None

    if args.all == 0 and args.offensive == "none":
        attackTOanalyse = utils.menu.menu()

    # Printing CLI 
    if args.offensive == "none":
        print(Fore.BLUE + Style.BRIGHT + "\nANALYSING the pcap...\n")
        print(Style.RESET_ALL)
        if args.verbose > 0:
            callAttacks(filePath, args, attackTOanalyse)
        else:
            callAttacks(filePath, args, attackTOanalyse)
    else:
        print(Fore.RED + Style.BRIGHT + "OFFENSIVE MODE ENGAGED")
        print(Style.BRIGHT + f"\t(trying to find {args.offensive.upper()} credentials in the pcap...)\n")
        print(Style.RESET_ALL)
        credentialSniff.credentialSniff(args.offensive, filePath)

    #STATS
    if(args.verbose > 0 and args.offensive == "none"):
        stats = basicStat(cap)
        print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
        print("\nGeneral stats:")
        for key, value in stats.items():
            if(key == 'total_packets'):
                print(f"\t{key} : {value}")
            elif(value != 0):
                round_value = round(value*100/stats['total_packets'],2)
                print(f"\t{key} : {value}\t{round_value} %")
    print()

