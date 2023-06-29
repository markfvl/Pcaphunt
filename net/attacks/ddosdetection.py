import pyshark
import hyperloglog
import sys
import time
import collections 
import nest_asyncio
nest_asyncio.apply()


def printer(arg):
    if arg != "erase_line":
        print(arg, end="\r")
    else: 
        sys.stdout.write("\x1b[2K") # erase line
        #sys.stdout.write("\x1b[1A") # cursor up one

def port_add(dict, pkt):
    if hasattr(pkt, 'tcp'): 
        dict['hll'].add(pkt.tcp.dstport)
    elif hasattr(pkt, 'udp'): 
        dict['hll'].add(pkt.udp.dstport)
    return dict


def dict_info(pkt, prev=None):

    info = {}

    if prev == None:
        info["start_time"] = pkt.frame_info.time_epoch
        info["victim_ip"] = pkt.ip.dst
        info["hll"] = hyperloglog.HyperLogLog(0.01)
        info["hll"].add(pkt.ip.src)
        info["dst_port"] = hyperloglog.HyperLogLog(0.01)
        info = port_add(info, prev)
        info = port_add(info, pkt)
        info['end_time'] = pkt.frame_info.time_epoch
    else:
        info["start_time"] = prev.frame_info.time_epoch
        info["end_time"] = pkt.frame_info.time_epoch
        info["victim_ip"] = pkt.ip.dst
        info["pkt_count"] = 1
        info["hll"] = hyperloglog.HyperLogLog(0.01)
        info["hll"].add(prev.ip.src)
        info["dst_port"] = hyperloglog.HyperLogLog(0.01)
        info = port_add(info, pkt)
    
    return info

def is_traffic_burst(dict, threshold):
    if ( int(dict.get("pkt_count")) > 1 and
        int(dict.get("pkt_count")) / ( float(dict.get("end_time")) - float (dict.get("start_time")) ) > (1 / threshold) ):
        return True
    else: 
        return False
    
def add_to_attackList(dict, attack_list, threshold):
    if is_traffic_burst(dict, threshold) and len(dict['dst_port']) <= 1:
        dict["botnet"] = len(dict.get('hll'))
        attack_list.append(dict)
    return attack_list
    
def ddos_dectection(cap, max_time):

    pkts_read = 0
    eqs_print = 0
    ddos_info = {} 
    ddos_attacks = []
    start = False
    prev = None
    cache = collections.deque() # capacity = 5
    not_found_in_cache = False

    for pkt in cap:

        # if not first packet and time difference between two 
        # consecutive packets is still in the threshold.
        if (pkts_read != 0 and pkt.ip.dst == prev.ip.dst and
            ((float(pkt.frame_info.time_epoch) - float(prev.frame_info.time_epoch)) < max_time)):
            if not start:
                ddos_info = dict_info(pkt, prev)
                cache.appendleft(ddos_info.copy())
                start = True
            ddos_info["hll"].add(pkt.ip.src)
            ddos_info['pkt_count'] += 1
            ddos_info = port_add(ddos_info, pkt)
        elif pkts_read != 0 and ((float(pkt.frame_info.time_epoch) - float(prev.frame_info.time_epoch)) < max_time):
            if not start:
                ddos_info = dict_info(prev)
                ddos_info['pkt_count'] = 1
                cache.appendleft(ddos_info)
                start = True
            ddos_info["end_time"] = prev.frame_info.time_epoch

            for entry in cache:
                # travel the dictionary, and update the parameters or add entry accordingly
                if (pkt.ip.dst == entry.get('victim_ip') and 
                    (float(pkt.frame_info.time_epoch) - float(entry.get("end_time")) < max_time) ):
                    not_found_in_cache = False
                    entry["hll"].add(pkt.ip.src)
                    entry = port_add(entry, pkt)
                    entry['pkt_count'] += 1
                    entry['end_time'] = pkt.frame_info.time_epoch
                    ddos_info = entry.copy() 
                    cache.appendleft(entry.copy()) 
                    cache.remove(entry)
                    break
                    
                # same ip.dst but time is greater than threshold
                # two possible attacks, the first one is finished
                # the second one has started
                elif pkt.ip.dst == entry.get('victim_ip'):
                    # if the pkt_count is greater than 1 and avg packets per second are greater than threshold
                    # add the possible attack to the attack list
                    add_to_attackList(entry, ddos_attacks, max_time)
                    cache.remove(entry)
                    ddos_info = dict_info(pkt)
                    ddos_info['pkt_count'] = 1
                    ddos_info['end_time'] = pkt.frame_info.time_epoch
                    cache.appendleft(ddos_info.copy())
                    not_found_in_cache = False
                    break

            if not_found_in_cache:
                # new dictionary
                ddos_info = dict_info(pkt)
                ddos_info['pkt_count'] = 1
                # check if last entry in cache is a traffic burst
                if len(cache) >= 5:
                    add_to_attackList(cache[4], ddos_attacks, max_time)
                    # pop last entry in the cache
                    cache.pop()
                cache.appendleft(ddos_info.copy())
                
        # if the time is too big between one packet and another the attack 
        # can be considered as finished
        elif pkts_read != 0:
            if not start:
                ddos_info = dict_info(prev)
                ddos_info['pkt_count'] = 1
                cache.appendleft(ddos_info)
                start = True
                
            ddos_info["end_time"] = prev.frame_info.time_epoch
            add_to_attackList(ddos_info, ddos_attacks, max_time)
            for entry in cache: 
                if entry == ddos_info:
                    cache.remove(entry)
                    break
            # re-write dict with new packet info
            ddos_info = dict_info(pkt)
            ddos_info["pkt_count"] = 1

        # every 500 packets print a part of an arrow
        pkts_read +=1
        if pkts_read % 500 == 0:
            arrow = "=" * eqs_print + ">"
            printer(arrow)
            eqs_print += 1
        
        prev = pkt
        not_found_in_cache = True

    # if the last packed in the for loop is part of the attack 
    # append the information retrived inside of the list
    if start:
        ddos_info["end_time"] = prev.frame_info.time_epoch
        add_to_attackList(ddos_info, ddos_attacks, max_time)
        for entry in cache:
            if dict_info != entry:
                add_to_attackList(entry, ddos_attacks, max_time)
        
    printer("erase_line")

    return ddos_attacks


def print_attacks(attackName, attack_list):

    attacks_number = len(attack_list)

    if attacks_number == 0:
        print(f"No traces of '{attackName}' have been found.\n")
        return
    elif attacks_number == 1:
        print(f"Traces of a DoS/DDoS '{attackName}' attack have been found:\n")
    elif attacks_number > 1:
        print(f"Traces of {attacks_number} DoS/DDoS '{attackName}' attacks have been found:\n")
    else:
        print(f"Something went WRONG with '{attackName}' detection.\n")      
        return
    
    for attack in attack_list:
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(attack.get('start_time'))))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(attack.get('end_time'))))
        print(f"START TIME: {start_time}\nEND TIME: {end_time}\n\tBotnet cardinality: {attack.get('botnet')}\n\tVictim IP: {attack.get('victim_ip')}\n")


# PING OF DEATH 
# A correctly formed ping packet is typically 56B
# or 64B when the ICMP header is considered and 84B including 
# IPv4 header
def pingOfDeathIPv4(filePath):

    pingOfDeathIPv4Filter = "icmp and not icmp.type == 3 and ip.len > 84"
    ping_of_death_IPv4_cap = pyshark.FileCapture(filePath, display_filter = pingOfDeathIPv4Filter)

    ping_of_death_attacks = ddos_dectection(ping_of_death_IPv4_cap, 1)
    print_attacks("Ping of Death (IPv4)", ping_of_death_attacks)

# ICMP FLOOD ATTACK
# normal ping send out a new packet each second  
def icmp_flood(filePath):

    echoReqFilter = "icmp.type == 8 and not icmp.type == 3"
    icmp_flood_cap  = pyshark.FileCapture(filePath, display_filter = echoReqFilter)

    icmp_attacks = ddos_dectection(icmp_flood_cap, 1)
    print_attacks("ICMP flood", icmp_attacks)

# TCP SYN FLOOD attack
def tcp_syn_flood(filePath):
    
    tcp_syn_filter = "tcp.flags.syn == 1 and tcp.flags.ack == 0"
    tcp_ack_filter = "tcp.flags.syn == 0 and tcp.flags.ack == 1"

    syn_cap = pyshark.FileCapture(filePath, display_filter = tcp_syn_filter)
    tcp_syn_attacks = ddos_dectection(syn_cap, 1)
    ack_hll = hyperloglog.HyperLogLog(0.01)
    
    # check if there is a real tcp syn flood attack
    for attack in tcp_syn_attacks:
        time_filter = f" and frame.time_epoch >= {attack.get('start_time')} and frame.time_epoch <= {attack.get('end_time')}"
        victim_filter = f" and ip.dst == {attack.get('victim_ip')}"
        filter = tcp_ack_filter + time_filter + victim_filter
        attack_cap = pyshark.FileCapture(filePath, display_filter=filter)
        for pkt in attack_cap:
            ack_hll.add(pkt.ip.src)
        ack_cardinality = len(ack_hll)
        syn_cardinality = int(attack.get('botnet'))
        if ack_cardinality / syn_cardinality > 1/3:
            tcp_syn_attacks.remove(attack)

        ack_hll = hyperloglog.HyperLogLog(0.01)

    print_attacks("TCP Syn flood", tcp_syn_attacks)

# DNS REQUEST FLOOD 
def dns_request_flood(filePath):

    dns_request_filter = "dns and dns.flags == 0x0100"
    dns_request_cap = pyshark.FileCapture(filePath, display_filter = dns_request_filter)

    dns_request_attacks = ddos_dectection(dns_request_cap, 1)

    start_time = None
    end_time = None
    attack_cap = None
    time_filter = ""
    pkt_count = 0
    # check if the suspicious traffic bursts really are dns request flood attacks
    for attack in dns_request_attacks:
        start_time = attack.get('start_time')
        end_time = attack.get('end_time')
        time_filter = f"frame.time_epoch >= {start_time} and frame.time_epoch <= {end_time} and not dns.flags == 0x0100"
        attack_cap = pyshark.FileCapture(filePath, display_filter=time_filter)
        for pkt in attack_cap:
            pkt_count +=1
        if(pkt_count / int(attack.get("pkt_count"))) > 1/5:
            dns_request_attacks.remove(attack)

    print_attacks("DNS request flood", dns_request_attacks)
