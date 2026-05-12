import torch
from torch.utils.data import Dataset
from torch_geometric.data import Batch
import os
import numpy as np
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, raw
import torch
import math
from config import Config as cfg
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops
import utils

class TrafficFlowDataset(Dataset):
    def __init__(self, headers_path, payloads_path, labels_path):
        """
        Expects the saved .pt files containing lists of PyG Data objects.
        """
        print("Loading datasets into memory...")
        self.headers = torch.load(headers_path)    # List of 50-graph lists
        self.payloads = torch.load(payloads_path)  # List of 50-graph lists
        self.labels = torch.load(labels_path)      # Tensor of labels
        
        assert len(self.headers) == len(self.payloads) == len(self.labels), "Data length mismatch!"
        print(f"Loaded {len(self.labels)} flows.")

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.headers[idx], self.payloads[idx], self.labels[idx]

def pyg_collate_fn(batch):
    """
    Takes a batch of flows and flattens the 50-packet sequences into large PyG Batches.
    """
    flat_headers =[]
    flat_payloads = []
    labels =[]
    
    for header_list, payload_list, label in batch:
        flat_headers.extend(header_list)      # Flatten 50 graphs
        flat_payloads.extend(payload_list)    # Flatten 50 graphs
        labels.append(label)
        
    # PyG's batching magic handles the disconnected subgraphs automatically
    header_batch = Batch.from_data_list(flat_headers)
    payload_batch = Batch.from_data_list(flat_payloads)
    labels_tensor = torch.tensor(labels, dtype=torch.long)
    
    return header_batch, payload_batch, labels_tensor


def construct_graph_pyg(byte_sequence, w_size, pmi_k=1):
    # If the packet is empty, return a dummy graph
    if len(byte_sequence) == 0:
        x = torch.tensor([[cfg.cfg.PAD_TRUNC_DIGIT]], dtype=torch.float32)
        edge_index = torch.tensor([[0], [0]], dtype=torch.long) # self loop
        return Data(x=x, edge_index=edge_index)
    
    windows = []
    seq_len = len(byte_sequence)
    if seq_len <= w_size:
        windows.append(byte_sequence)
    else:
        for j in range(seq_len - w_size + 1):
            windows.append(byte_sequence[j : j + w_size])

    # Computing PMI
    word_window_freq = {} # P(x)
    word_pair_count = {} # P(x,y)

    for window in windows:
        appeared = set()
        for i, byte_i in enumerate(window):
            if byte_i not in appeared:
                word_window_freq[byte_i] = word_window_freq.get(byte_i, 0) + 1
                appeared.add(byte_i)
        
            for j in range(i + 1, len(window)):
                byte_j = window[j]
                if byte_i == byte_j:
                    continue
                pair1, pair2 = f"{byte_i},{byte_j}", f"{byte_j},{byte_i}"
                word_pair_count[pair1] = word_pair_count.get(pair1, 0) + 1
                word_pair_count[pair2] = word_pair_count.get(pair2, 0) + 1

    num_windows = len(windows)
    src, dst, weight = [], [], []

    for pair, count in word_pair_count.items():
        b1, b2 = map(int, pair.split(','))
        freq1, freq2 = word_window_freq[b1], word_window_freq[b2]
        
        pmi = math.log((1.0 * count / num_windows)**pmi_k / 
                       (1.0 * freq1 * freq2 / (num_windows * num_windows)))
        
        if pmi > 0:
            src.append(b1)
            dst.append(b2)
            weight.append(pmi)

    # Map to 0...N continuous node IDs
    bytes2id = {}
    feat =[]
    id_count = 0
    for byte in src:
        if byte not in bytes2id:
            bytes2id[byte] = id_count
            id_count += 1
            feat.append([byte])
            
    # Fallback if no edges passed the PMI > 0 threshold
    if len(src) == 0:
        unique_bytes = list(set(byte_sequence))
        x = torch.tensor([[b] for b in unique_bytes], dtype=torch.float32)
        edge_index = torch.arange(len(unique_bytes)).view(1, -1).repeat(2, 1)
        return Data(x=x, edge_index=edge_index)

    mapped_src = [bytes2id[b] for b in src]
    mapped_dst = [bytes2id[b] for b in dst]

    x = torch.tensor(feat, dtype=torch.float32)
    edge_index = torch.tensor([mapped_src, mapped_dst], dtype=torch.long)
    edge_index, _ = add_self_loops(edge_index, num_nodes=x.size(0))

    return Data(x=x, edge_index=edge_index)


def process_file_into_flows(npz_file, label_idx):
    """Reads an NPZ file, splits it into 50-packet chunks, and converts to PyG Data."""
    try:
        data = np.load(npz_file, allow_pickle=True)
        raw_headers = data['header']
        raw_payloads = data['payload']
    except Exception as e:
        print(f"Error loading {npz_file}: {e}")
        return [],[]
    
    # Filter out empty packets first (like the original paper did)
    valid_indices =[i for i, (h, p) in enumerate(zip(raw_headers, raw_payloads)) if len(p) > 0 and len(h) > 0]
    valid_headers = [list(raw_headers[i]) for i in valid_indices]
    valid_payloads = [list(raw_payloads[i]) for i in valid_indices]

    flow_headers =[]
    flow_payloads =[]

    # Chunk into sizes of 50 (cfg.FLOW_PAD_TRUNC_LENGTH)
    for i in range(0, len(valid_headers), cfg.FLOW_PAD_TRUNC_LENGTH):
        chunk_headers = valid_headers[i : i + cfg.FLOW_PAD_TRUNC_LENGTH]
        chunk_payloads = valid_payloads[i : i + cfg.FLOW_PAD_TRUNC_LENGTH]
        
        # We don't want flows that are too small (e.g., just 1 or 2 packets).
        # Flow must have at least 5 packets to be considered valid.
        if len(chunk_headers) < 5:
            continue

        h_graph_list = []
        p_graph_list =[]

        # Process each packet in the chunk
        for pkt_h, pkt_p in zip(chunk_headers, chunk_payloads):
            
            # Header preprocessing
            pkt_h = utils.strip_ips_and_ports(pkt_h)[:cfg.HEADER_MAX_LEN]
            if cfg.PAD_BYTES and len(pkt_h) < cfg.HEADER_MAX_LEN:
                pkt_h.extend([cfg.PAD_TRUNC_DIGIT] * (cfg.HEADER_MAX_LEN - len(pkt_h)))
            h_graph_list.append(construct_graph_pyg(pkt_h, cfg.PMI_WINDOW_SIZE**2))
            
            # Payload preprocessing
            pkt_p = pkt_p[:cfg.PAYLOAD_MAX_LEN]
            if cfg.PAD_BYTES and len(pkt_p) < cfg.PAYLOAD_MAX_LEN:
                pkt_p.extend([cfg.PAD_TRUNC_DIGIT] * (cfg.PAYLOAD_MAX_LEN - len(pkt_p)))
            p_graph_list.append(construct_graph_pyg(pkt_p, cfg.PMI_WINDOW_SIZE**2))

        # Pad the flow up to 50 items (Sequence Padding for LSTM)
        dummy_h = [cfg.PAD_TRUNC_DIGIT] * cfg.HEADER_MAX_LEN if cfg.PAD_BYTES else []
        dummy_p =[cfg.PAD_TRUNC_DIGIT] * cfg.PAYLOAD_MAX_LEN if cfg.PAD_BYTES else[]
        
        while len(h_graph_list) < cfg.FLOW_PAD_TRUNC_LENGTH:
            h_graph_list.append(construct_graph_pyg(dummy_h, cfg.PMI_WINDOW_SIZE**2))
            p_graph_list.append(construct_graph_pyg(dummy_p, cfg.PMI_WINDOW_SIZE**2))

        flow_headers.append(h_graph_list)
        flow_payloads.append(p_graph_list)

    return flow_headers, flow_payloads