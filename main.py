from kafka import KafkaProducer
from snortunsock import snort_listener
import time
import dpkt
import socket
import json

TOPIC = "snort"
KEY = "snort"

def publish_message(producer_instance, topic_name, key, value):
    try:
        print(value)
        key_bytes = bytes(key, encoding='utf-8')
        value_bytes = bytes(value, encoding='utf-8')
        producer_instance.send(topic_name, key=key_bytes, value=value_bytes)
        producer_instance.flush()
        print('Message published successfully.')
    except Exception as ex:
        print('Exception in publishing message')
        print(ex)

def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)

def ip6_to_str(address):
    return socket.inet_ntop(socket.AF_INET6, address)

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(chr(x)) for x in address)

def main():
    kafka_producer = KafkaProducer(
        bootstrap_servers = ['10.252.175.154:9092'],
        api_version=(0, 10)
    )

    snort_message = {}
    list_protocol = ["HOPOPT","ICMP","IGMP","GGP","IP-in-IP","ST","TCP","CBT","EGP","IGP","BBN-RCC-MON", "NVP-II","PUP","ARGUS","EMCON","EXNET","CHAOS","UDP","MUX","DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","DCCP","3PC","IDPR","XTP","DDP","IDPR-CMTP","TP++","IL","IPv6","SDRP","IPv6-Route","IPv6-Frag","IDRP","RSVP","GREs","DSR","BNA","ESP","AH","I-NLSP","SWIPE","NARP","MOBILE","TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","Host Internal Protocol","CFTP","Any Local Network","SAT-EXPAK","KRYPTOLAN","RVD","IPPC","Any Distributed File System","SAT-MON","VISA","IPCU","CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK","ISO-IP","VMTP","SECURE-VMTP","VINES","TTP/IPTMP","NSFNET-IGP","DGP","TCF","EIGRP","OSPF","Sprite-RPC","LARP","MTP","AX.25","OS","MICP","SCC-SP","ETHERIP","ENCAP","Any Private Encryption Scheme","GMTP","IFMP","PNNI","PIM","ARIS","SCPS","QNX","A/N","IPComp","SNP","Compaq-Peer","IPX-in-IP","VRRP","PGM","Any 0-hop Protocol","L2TP","DDX","IATP","STP","SRP","UTI","SMP","SM","PTP","IS-IS over IPv4","FIRE","CRTP","CRUDP","SSCOPMCE","IPLT","SPS","PIPE","SCTP","FC","RSVP-E2E-IGNORE","Mobility Header","UDPLite","MPLS-in-IP","manet","HIP","Shim6","WESP","ROHC","UNASSIGNED","EXPERIMENT","RESERVED"]

    for msg in snort_listener.start_recv("/var/log/snort/snort_alert"):
        print("")
        print("Message : ", msg.__dict__)
        orig_msg = b'.'.join(msg.alertmsg)
        am = (str(orig_msg, 'utf-8').replace("\u0000", "")).replace("'", "")
        snort_message["timestamp"] = str(time.time())
        snort_message["alert_msg"] = str(am)

        print('alertmsg: %s' % str(am))

        buf = msg.pkt
        event = msg.event
        snort_message["company"] = "company"
        snort_message["device_id"] = "device_id"
        snort_message["sig_gen"] = event.sig_generator
        snort_message["sig_id"] = event.sig_rev
        snort_message["classification"] = event.classification
        snort_message["priority"] = event.priority

        print("Event : ", event.__dict__)
        print("Reftime : ", event.ref_time.__dict__)

        eth = dpkt.ethernet.Ethernet(buf)
        src_mac = mac_addr(eth.src)
        dest_mac = mac_addr(eth.dst)

        snort_message["src_mac"] = src_mac
        snort_message["dest_mac"] = dest_mac

        if eth.data.p == 255:
            snort_message["protocol"] = list_protocol[145]
        elif eth.data.p <= 254 and eth.data.p >= 253:
            snort_message["protocol"] = list_protocol[144]
        elif eth.data.p <= 252 and eth.data.p >= 143:
            snort_message["protocol"] = list_protocol[143]
        else:
            snort_message["protocol"] = list_protocol[eth.data.p]

        try:
            eth.data.data.dport
        except AttributeError:
            snort_message["dst_port"] = 0
        else:
            snort_message["dst_port"] = eth.data.data.dport

        try:
            eth.data.data.sport
        except AttributeError:
            snort_message["src_port"] = 0
        else:
            snort_message["src_port"] = eth.data.data.sport
        
        print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip_type = "IPv6"
            snort_message["ip_type"] = ip_type

            ip = eth.data
            src_ip = ip6_to_str(ip.src)
            dest_ip = ip6_to_str(ip.dst)
            len = ip.plen
            hop_lim = ip.hlim
            packet_info = {"len": len, "hop_limit": hop_lim}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            print('IP: %s -> %s   (len=%d hop_limit=%d)\n' % \
                  (ip6_to_str(ip.src), ip6_to_str(ip.dst), ip.plen, ip.hlim))
        
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_type = "IPv4"
            snort_message["ip_type"] = ip_type

            ip = eth.data

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            src_ip = ip_to_str(ip.src)
            dest_ip = ip_to_str(ip.dst)
            len = ip.len
            ttl = ip.ttl
            DF = do_not_fragment
            MF = more_fragments
            offset = fragment_offset
            packet_info = {"len": len, "ttl": ttl, "DF": DF, "MF": MF, "offset": offset}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            # Print out the info
            #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
            #      (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
            #       fragment_offset))

        else:
            ip_type = "Unsupported"
            snort_message["ip_type"] = ip_type

            src_ip = "N/A"
            dest_ip = "N/A"
            packet_info = {"not_supported_packet": "IP Packet unsupported"}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)

        # snort_mqtt.publish(topic, json.dumps(snort_message))
        # kafka_producer.send(TOPIC, key=KEY, value=snort_message)
        snort_message_json = json.dumps(snort_message)
        publish_message(kafka_producer, TOPIC, KEY, snort_message_json)

if __name__ == "__main__":
    main()