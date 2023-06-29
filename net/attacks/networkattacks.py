import pyshark
import re
import time
import nest_asyncio
nest_asyncio.apply()

##################### SPOOFING ##########################

def arpSpoofing(filePath):

    ArpSpoofingfilter = "arp.duplicate-address-detected or arp.duplicate-address-frame"
    arp_spoofing_cap = pyshark.FileCapture(filePath, display_filter = ArpSpoofingfilter)

    attackerMacAddr = None
    macFound = False
    arpSpoofedPkts = 0
    for pkt in arp_spoofing_cap:
        arpSpoofedPkts +=1
        if(not macFound and 'ETH' in pkt):
            attackerMacAddr = pkt.eth.addr
            macFound = True
    
    if arpSpoofedPkts > 1:
        print("\nTraces of an 'ARP Spoofing' attack have been found.\n\tPoisonus packets found: {}".format(arpSpoofedPkts)+"\n")
    else:
        print("No traces of 'Arp Spoofing' have been found.\n")


##################### DOS ##########################

'''PACKET LOSS
   unexpected packet loss combined with possible traces of dos/ddos attack is a sign that bolster a lot 
   the option of a successfully executed dos/ddos attack although alone many packet re-transmissions and
   missing packets may indicate a severe problem in the network'''
def packet_loss(filePath):

    pkt_loss_filter = "tcp.analysis.lost_segment or tcp.analysis.retransmission"
    packet_loss_cap = pyshark.FileCapture(filePath, display_filter = pkt_loss_filter)
    pktLossCounter = 0

    for pkt in packet_loss_cap:
        pktLossCounter += 1
    
    if pktLossCounter == 0: 
        print("No unexpected 'Packet Loss' have been found.\n")
        return 0
    
    tcp_cap = pyshark.FileCapture(filePath, display_filter="tcp")
    tcp_packets = 0
    for pkt in tcp_cap:
        tcp_packets +=1
    
    lossRatio = pktLossCounter / tcp_packets
    if(lossRatio < 1/4):
        print("No unexpected 'Packet Loss' have been found.\n")
        return 0
    else:
        message = "Unexpected 'Packets Loss' have been found."
        print(f"{message}\n\tpackets lost / re-transmitted = {pktLossCounter}\n\ttotal tcp packets = {tcp_packets}\n")
        if(lossRatio > 1/2):
            return 2
        else:
            return 1
        return 2
    
    
##################### VLAN/CISCO ##########################

'''Check if there are any DTP (Dsynamic Trunking Protocol) or packets tagged with 
   multiple Vlan tags'''
def vlan_hopping(filePath):

    vlan_hop_filter = "dtp or vlan.too_many_tags"   
    vlan_hopping_cap = pyshark.FileCapture(filePath, display_filter = vlan_hop_filter)
    pktHopCount = 0
    
    for pkt in vlan_hopping_cap:
        pktHopCount += 1
    if(pktHopCount > 1):
        print("Traces of a possible 'Vlan Hopping' attack have been found:\n\tPoisonus packets = {}".format(pktHopCount))
    else:
        print("No traces of 'Vlan Hopping' exploitation have been found.")
    print()


################# OTHERS ##################

def url_redirection(filePath, verbose):
    redirection_filter = "http.response.code > 299 and http.response.code < 400"
    redirection_cap = pyshark.FileCapture(filePath, display_filter= redirection_filter)

    parameter_redirection_list = []
    other_redirection_list = []
    url_dict = {}
    start_time = None
    end_time = None

    for pkt in redirection_cap:
        if start_time == None:
            start_time = pkt.frame_info.time_epoch
        end_time = pkt.frame_info.time_epoch
        
        url_dict['uri'] = pkt.http.response_for_uri
        url_dict['ip'] = pkt.ip.src
        url = re.search('http://(.+?)/', url_dict['uri'])
        url_dict['url'] = url.group(1)

        if url_dict['url'].startswith("www."):
            url_dict['url'] = url_dict['url'][4:]

        if pkt.http.response_code == "301" or pkt.http.response_code == "302":
            parameter_redirection_list.append(url_dict.copy())
        else:
            other_redirection_list.append(url_dict.copy())
    
    if (len(parameter_redirection_list) + len(other_redirection_list)) == 0:
        print("No traces of 'URL redirection' have been found.\n")
        
    elif len(parameter_redirection_list) > 0:
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(start_time)))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(end_time)))
        
        print(f"Found traces of 'Parameter Based URL Redirection': START = {start_time}\tEND = {end_time}")
        for url in parameter_redirection_list:
            print(f"\tRedirected URL: {url['url']}, IP: {url['ip']}")
            if verbose > 0:
                print(f"\tFull URI requested: {url['uri']}\n")
    elif len(other_redirection_list) > 0:
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(start_time)))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(end_time)))
        
        print(f"Found traces of 'URL Redirection': START = {start_time}\tEND = {end_time}")
        for url in parameter_redirection_list:
            print(f"\tRedirected URL: {url['url']}, IP: {url['ip']}")
            if verbose > 0:
                print(f"\tFull URI requested: {url['uri']}\n")
    print()
