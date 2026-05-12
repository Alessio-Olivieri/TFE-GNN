import os
import numpy as np
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, raw
import torch
import math
from config import Config as cfg
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops

def process_pcap(pcap_path):
    p_header_list = []
    p_payload_list = []
    payload_length =[]
    pkt_length = []
    src_ip = []
    dst_ip = []
    src_port =[]
    dst_port = []
    time_list = []
    protocol = []
    flag_list =[]
    mss_list =[]
    
    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            # Skip non-IP traffic
            if (IP not in pkt and IPv6 not in pkt) or (TCP not in pkt and UDP not in pkt):
                continue
            
            net_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            trans_layer = pkt[TCP] if TCP in pkt else pkt[UDP]
            
            # Extract raw bytes
            raw_pkt_bytes = raw(net_layer)
            payload_bytes = raw(trans_layer.payload)
            
            # Calculate header bytes
            header_len = len(raw_pkt_bytes) - len(payload_bytes)
            header_bytes = bytearray(raw_pkt_bytes[:header_len])
            
            # Store Metadata
            payload_length.append(len(payload_bytes))
            pkt_length.append(len(raw_pkt_bytes))
            src_ip.append(net_layer.src)
            dst_ip.append(net_layer.dst)
            src_port.append(trans_layer.sport)
            dst_port.append(trans_layer.dport)
            time_list.append(float(pkt.time))
            protocol.append(net_layer.proto)
            
            # TCP specific fields (Safely handle UDP if it exists)
            if TCP in pkt:
                flag_list.append(pkt[TCP].flags.value)
                # Extract MSS (Maximum Segment Size) from options
                mss_val = 0
                for opt_name, opt_val in pkt[TCP].options:
                    if opt_name == 'MSS':
                        mss_val = opt_val
                mss_list.append(mss_val)
            else:
                flag_list.append(0)
                mss_list.append(0)
                
            # Convert bytes to lists of integers for the GNN
            p_header_list.append(list(header_bytes))
            p_payload_list.append(list(payload_bytes))

    return {
        "header": np.array(p_header_list, dtype=object),
        "payload": np.array(p_payload_list, dtype=object),
        "payload_length": np.array(payload_length, dtype=object),
        "pkt_length": np.array(pkt_length, dtype=object),
        "src_ip": np.array(src_ip, dtype=object),
        "dst_ip": np.array(dst_ip, dtype=object),
        "src_port": np.array(src_port, dtype=object),
        "dst_port": np.array(dst_port, dtype=object),
        "time": np.array(time_list, dtype=object),
        "protocol": np.array(protocol, dtype=object),
        "flag": np.array(flag_list, dtype=object),
        "mss": np.array(mss_list, dtype=object)
    }

def pcap2npy(pcap_path, save_path):
    print(f"Processing {pcap_path}...")
    data_dict = process_pcap(pcap_path)
    
    np.savez_compressed(save_path, **data_dict)
    print(f"Saved to {save_path}")

    
def strip_ips_and_ports(packet_bytes):
    """
    slice out bytes 12-19 (IPs) and 20-23 (Ports).
    """
    if len(packet_bytes) < 24:
        return packet_bytes
    ip_part = packet_bytes[:12]
    rest_part = packet_bytes[24:]
    return ip_part + rest_part


if __name__ == '__main__':
    pass

