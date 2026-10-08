"""Packet-local PMI graphs adapted from the original PyG implementation.

Graph construction is unchanged from the implementation used for the results.
The experiment pipeline supplies padded, nonempty byte sequences.
"""
import math
import torch
from torch_geometric.data import Data
from torch_geometric.utils import add_self_loops
from src.config import Config as cfg

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


