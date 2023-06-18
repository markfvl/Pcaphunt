import sys
try:
    import radix
except ImportError:
    print("Py-Radix is not installed on the system, therefore port scan detection is not usable.\n")
    sys.exit(-1)
import time
import pyshark
import hyperloglog
import nest_asyncio
nest_asyncio.apply()


def print_scans(scan_list, name):
    if len(scan_list) > 0:
        for scan in scan_list:
            start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(scan.get('start'))))
            end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(scan.get('end'))))
            print(f"Found {name} - Attacker = {scan['src']}\tVictim = {scan['dst']}:\n\tStart = {start_time}\n\tEnd = {end_time}\n\tPort Scanned (estimated) = {scan['cardinality']}")
    else:
        print(f"No traces of {name} have been found")
    print("")


def dict_info(pkt, update = False, dict = {}, prev = None):
    if update == False:
        dict['hll'] = hyperloglog.HyperLogLog(0.01)
        if prev == None:
            dict['start_time'] = pkt.frame_info.time_epoch
        else:
            dict['start_time'] = prev.frame_info.time_epoch

    dict['end_time'] = pkt.frame_info.time_epoch
    return port_add(dict, pkt)


def port_add(dict, pkt):
    if hasattr(pkt, 'tcp'): 
        dict['hll'].add(pkt.tcp.dstport)
    elif hasattr(pkt, 'udp'): 
        dict['hll'].add(pkt.udp.dstport)
    return dict


def check_time(pkt, dict, maxTime):
    if float(pkt.frame_info.time_epoch) - float(dict['end_time']) < maxTime:
        return True
    else:
        return False
    

def update_srcNode(pkt, max_time, node = None, tree = None):
    if node == None:
        node = tree.add(pkt.ip.src)
        node.data['info'] = []
        node.data['info'].append(dict_info(pkt))

    if check_time(pkt, node.data['info'][-1], max_time):
        node.data['info'][-1] = dict_info(pkt, True, node.data['info'][-1]).copy()
    else:
        node.data['info'].append(dict_info(pkt).copy())
    return node


def create_dstNode(tree, pkt, max_time, prev = None):
    node = tree.add(pkt.ip.dst)
    node.data['rtree_src'] = radix.Radix()
    src_node = None
    src_node = update_srcNode(pkt, max_time, src_node, node.data['rtree_src'])
    return node


def search_srcNode(dst_tree, pkt, dst_node = None):
    if dst_node == None:
        for node in dst_tree:
            if node.network == pkt.ip.dst:
                dst_node = node
                src_tree = node.data['rtree_src']
                for src_node in src_tree:
                    if src_node.network == pkt.ip.src:
                        return [0, src_node]
    else:
        for src_node in dst_node.data['rtree_src']:
            if src_node.network == pkt.ip.src:
                return [0, src_node]
    if dst_node == None:
        return [-1, None]
    return [-2, dst_node]


def port_scan_traffic(cap, max_time):

    prev = None 
    rtree_dst = radix.Radix()
    start = True
    src_node = None

    for pkt in cap:
        if prev != None and pkt.ip.dst == prev.ip.dst and pkt.ip.src == prev.ip.src:
            if start:
                dst_node = create_dstNode(rtree_dst, pkt, max_time, prev)
                src_node = search_srcNode(rtree_dst, pkt, dst_node)
                src_node = src_node[1]
                start = False
            src_node = update_srcNode(pkt, max_time, src_node, None)

        elif prev != None and pkt.ip.dst == prev.ip.dst:
            if start:
                dst_node = create_dstNode(rtree_dst, pkt, max_time)
                src_node = search_srcNode(rtree_dst, pkt, dst_node)
                src_node = src_node[1]
                start = False
            src_node = search_srcNode(rtree_dst, pkt, dst_node) 
            if src_node[0] == 0:
                src_node = update_srcNode(pkt, max_time, src_node[1])
            else:
                src_node = update_srcNode(pkt, max_time, None, src_node[1].data['rtree_src'])

        elif prev != None:
            if start:
                dst_node = create_dstNode(rtree_dst, prev, max_time)
                dst_node = create_dstNode(rtree_dst, pkt, max_time)
                start = False

            src_node = search_srcNode(rtree_dst, pkt)
            if src_node[0] == -1:
                dst_node = create_dstNode(rtree_dst, pkt, max_time)
                src_node = search_srcNode(rtree_dst, pkt, dst_node)
                src_node = src_node[1]
            elif src_node[0] == -2:
                src_node = src_node[1]
                src_node = update_srcNode(pkt, max_time, dst_node, rtree_dst)
            else:
                src_node = update_srcNode(pkt, max_time, src_node[1])
           
        prev = pkt    

    # creating list of port scans
    scans_list = []
    scan_info = {}
    for dst_node in rtree_dst:
        for src_node in dst_node.data['rtree_src']:
            for elem in src_node.data['info']:
                if len(elem['hll']) > 1:
                    scan_info['dst'] = dst_node.network
                    scan_info['src'] = src_node.network
                    scan_info['start'] = elem['start_time']
                    scan_info['end'] = elem['end_time']
                    scan_info['cardinality'] = len(elem['hll'])
                    scans_list.append(scan_info.copy())
                    
    return scans_list


def port_scan(filePath):

    maxTime = 60

    tcp_syn_scans = []
    tcp_ack_scans = []
    tcp_connect_scans= []
    udp_scans = []
    
    syn_filter = "tcp.flags.syn == 1 and tcp.flags.ack == 0"
    syn_cap = pyshark.FileCapture(filePath, display_filter = syn_filter)
    syn_portScans = port_scan_traffic(syn_cap, maxTime)

    ack_filter = "tcp.flags.syn == 0 and tcp.flags.ack == 1"
    
    if len(syn_portScans) > 0:
        
        for scan in syn_portScans:
            time_filter = f"frame.time_epoch > {scan['start']} and frame.time_epoch < {scan['end']}"
            ip_filter = f"ip.src == {scan['src']} and ip.dst == {scan['dst']}"
            ack_filter = ack_filter + " and " + time_filter + " and " + ip_filter
            ack_cap = pyshark.FileCapture(filePath, display_filter = ack_filter)
            ack_portScans = port_scan_traffic(ack_cap, maxTime) 

            if len(ack_portScans) == 1:
                # full connection
                if ack_portScans[0]['cardinality'] > 1/2 * scan['cardinality']:
                    scan_to_add = scan.copy()
                    scan_to_add['end'] = ack_portScans[0]['end']
                    tcp_connect_scans.append(scan_to_add.copy())
                # tcp syn scan
                else:
                    tcp_syn_scans.append(scan.copy())
            elif len(ack_portScans) == 0:
                    tcp_syn_scans.append(scan.copy())
            else:
                print("Something has gone wrong while analyzing the scan")
    else:
        # tcp ack scan
        ack_cap = pyshark.FileCapture(filePath, display_filter = ack_filter)
        ack_portScans = port_scan_traffic(ack_cap, maxTime) 
        if len(ack_portScans) > 0:
            tcp_ack_scans = ack_portScans

    # udp scan
    udp_filter = "udp"
    udp_cap = pyshark.FileCapture(filePath, display_filter = udp_filter)
    udp_portScans = port_scan_traffic(udp_cap, maxTime)
    if len(udp_portScans) > 0:
        udp_scans = udp_portScans
        
    # printing results
    print_scans(tcp_syn_scans, "TCP SYN port scan")
    print_scans(tcp_ack_scans, "TCP ACK port scan")
    print_scans(tcp_connect_scans, "TCP connect port scan")
    print_scans(udp_scans, "UDP port scan")

