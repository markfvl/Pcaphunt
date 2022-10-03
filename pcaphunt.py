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

from net.attacks.networkattacks import *
from net.recon.hostdiscovery import *
from net.offense import credentialSpoof

from utils.parser import *
from utils.pcapStat import *
import utils.menu

####################### CALL ATTACKS ###########################


def callAttacks(filePath, stats, args, attackTOAnalyse):

    attacks = [arpSpoofing, packet_loss, pingOfDeathIPv4, icmpFlood, 
                syn_flood, dns_req_flood, vlan_hopping]
    if args.scapy > 0:
        from net.recon.hostdiscoveryScapy import arp_scanningScapy
        scans = [arp_scanningScapy, IP_protocol_scan, icmp_ping_sweeps_scan, 
                tcp_syn_ping_sweep, tcp_ack_ping_sweep, udp_ping_scan]
    else:
        scans = [arp_scanning, IP_protocol_scan, icmp_ping_sweeps_scan, 
                tcp_syn_ping_sweep, tcp_ack_ping_sweep, udp_ping_scan]

    if(args.all > 0 or attackTOanalyse[0] == 3):
        print("RECON: \n")
        allScans(scans, filePath)
        print("\nNETWORK ATTACKS: \n")
        allAttacks(attacks, filePath, stats)
    elif(attackTOanalyse[0] == 1):
        if(attackTOanalyse[1] == 1): #Spoof
            if(attackTOanalyse[2] == 1):
                attacks[0](filePath)
        elif(attackTOanalyse[1] == 2): #DDoS
            if(attackTOanalyse[2] == 1):
                attacks[1](filePath, stats['tcp_packets'])
            elif(attackTOanalyse[2] == 5):
                attacks[5](filePath, stats['total_packets'])
            elif(attackTOanalyse[2] == 6):
                allAttacks(attacks[1:6], filePath, stats)
            else:
                attacks[attackTOanalyse[2]](filePath)
        elif(attackTOanalyse[1] == 3): # Vlan
            if(attackTOanalyse[2] == 1):
                attacks[-1](filePath)
        elif(attackTOanalyse[1] == 4): # All attacks
            allAttacks(attacks, filePath, stats)
    elif(attackTOanalyse[0] == 2):
        if(attackTOanalyse[1] == 1):
            if attackTOanalyse[2] !=  7:
                scans[attackTOanalyse[2]](filePath)
            else:
                allScans(scans, filePath)
    else:
        print("Some error has accurred, quitting...")
        sys.exit(-1)
        

def allAttacks(attacks, filePath, stats):
    for a in attacks:
            if a == packet_loss:
                a(filePath, stats['tcp_packets'])
            elif a == dns_req_flood:
                a(filePath, stats['total_packets'])
            else:
                a(filePath)

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
    parser.add_argument("-v", "--verbose", help="Verbose mode (-vv for double verbose)", action="count", default=0)
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

    if args.offensive == "none":
        print(Fore.BLUE + Style.BRIGHT + "\nANALYSING the pcap...\n")
        stats = basicStat(cap)
        print("Done. Starting scanning for attacks...\n")
        print(Style.RESET_ALL)
        callAttacks(filePath, stats, args, attackTOanalyse)
    else:
        print(Fore.RED + Style.BRIGHT + "OFFENSIVE MODE ENGAGED")
        print(Style.BRIGHT + f"\t(trying to find {args.offensive.upper()} credentials in the pcap...)\n")
        print(Style.RESET_ALL)
        credentialSpoof.credentialSpoof(args.offensive, filePath)

    #STATS
    if(args.verbose > 0 and args.offensivr == "none"):
        print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
        print("\nGeneral stats:")
        for key, value in stats.items():
            if(key == 'total_packets'):
                print(f"\t{key} : {value}")
            elif(value != 0):
                print(f"\t{key} : {value}\t({value*100/stats['total_packets']}%)")
    print()

