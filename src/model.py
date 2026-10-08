"""PyTorch Geometric adaptation of the TFE-GNN architecture (Apache-2.0).

Based on Zhang et al., "TFE-GNN: A Temporal Fusion Encoder Using Graph Neural
Networks for Fine-grained Encrypted Traffic Classification", WWW 2023.
Upstream: https://github.com/ViktorAxelsen/TFE-GNN (see LICENSE and NOTICE).
Modified for PyG and the validated project encoder/branch-ablation semantics.
Payload and TLS ciphertext randomization are separate input transformations.
"""
import math

import torch
from torch import nn
from torch_geometric.nn import SAGEConv, global_mean_pool

FLOW_PAD_TRUNC_LENGTH = 50

class GraphSAGEEncoder(nn.Module):
    def __init__(self, embedding_size, h_feats, dropout, *, _validated_init=True):
        super(GraphSAGEEncoder, self).__init__()
        self.gcn_out_dim = 4 * h_feats

        # 257 to account for 0-255 bytes + 256 padding token
        self.embedding = nn.Embedding(257, embedding_size)

        # PyG SAGEConv does not take norm/activation automatically
        self.gcn1 = SAGEConv(embedding_size, h_feats, aggr='mean')
        self.bn1 = nn.BatchNorm1d(h_feats)
        self.act1 = nn.PReLU(h_feats)

        self.gcn2 = SAGEConv(h_feats, h_feats, aggr='mean')
        self.bn2 = nn.BatchNorm1d(h_feats)
        self.act2 = nn.PReLU(h_feats)

        self.gcn3 = SAGEConv(h_feats, h_feats, aggr='mean')
        self.bn3 = nn.BatchNorm1d(h_feats)
        self.act3 = nn.PReLU(h_feats)

        self.gcn4 = SAGEConv(h_feats, h_feats, aggr='mean')
        self.bn4 = nn.BatchNorm1d(h_feats)
        self.act4 = nn.PReLU(h_feats)

        self.dropout = nn.Dropout(dropout)

        if _validated_init:
            # DGL SAGEConv uses Glorot weights with ReLU gain, unlike PyG's default.
            # PyG's neighbor bias plus bias-free root is algebraically the same
            # single bias as DGL's bias-free neighbor plus biased root.
            for layer in (self.gcn1, self.gcn2, self.gcn3, self.gcn4):
                nn.init.xavier_uniform_(layer.lin_l.weight, gain=math.sqrt(2))
                nn.init.xavier_uniform_(layer.lin_r.weight, gain=math.sqrt(2))
                bound = 1 / math.sqrt(layer.lin_l.in_channels)
                nn.init.uniform_(layer.lin_l.bias, -bound, bound)

    def forward(self, x, edge_index, batch):
        h = self.embedding(x.long().view(-1))
        outputs = []
        for i in range(1, 5):
            if i < 4:
                h = self.dropout(h)  # upstream feat_drop: before aggregation
            h = getattr(self, f'gcn{i}')(h, edge_index)
            h = getattr(self, f'act{i}')(h)
            h = getattr(self, f'bn{i}')(h)
            outputs.append(h)
        return global_mean_pool(torch.cat(outputs, dim=1), batch)


class CrossGatedInfoFilter(nn.Module):
    def __init__(self, in_size):
        super(CrossGatedInfoFilter, self).__init__()
        self.filter1 = nn.Sequential(
            nn.Linear(in_size, in_size),
            nn.PReLU(FLOW_PAD_TRUNC_LENGTH),
            nn.Linear(in_size, in_size)
        )
        self.filter2 = nn.Sequential(
            nn.Linear(in_size, in_size),
            nn.PReLU(FLOW_PAD_TRUNC_LENGTH),
            nn.Linear(in_size, in_size)
        )

    def forward(self, x, y):
        z1 = self.filter1(x).sigmoid() * y
        z2 = self.filter2(y).sigmoid() * x
        return torch.cat([z1, z2], dim=-1)

class TFEGNN(nn.Module):
    def __init__(self, num_classes=6, embedding_size=64, h_feats=128, dropout=0.2, downstream_dropout=0.0, payload_mode="real"):
        super(TFEGNN, self).__init__()
        self.header_graphConv = GraphSAGEEncoder(embedding_size, h_feats, dropout, _validated_init=False)
        self.payload_graphConv = GraphSAGEEncoder(embedding_size, h_feats, dropout, _validated_init=False)

        self.gcn_out_dim = 4 * h_feats
        self.gated_filter = CrossGatedInfoFilter(in_size=self.gcn_out_dim)
        self.rnn = nn.LSTM(input_size=self.gcn_out_dim * 2, hidden_size=self.gcn_out_dim * 2,
                           num_layers=2, bidirectional=True, dropout=downstream_dropout, batch_first=True)
        self.fc = nn.Sequential(
            nn.Linear(in_features=self.gcn_out_dim * 4, out_features=self.gcn_out_dim),
            nn.PReLU(self.gcn_out_dim)
        )
        self.cls = nn.Linear(in_features=self.gcn_out_dim, out_features=num_classes)

        # Preserve the validated constructor's RNG sequence: initial PyG
        # encoders, fusion/LSTM/head, then replacement DGL-initialized encoders.
        # Removing these draws changes seeded initialization and training order.
        self.header_graphConv = GraphSAGEEncoder(embedding_size, h_feats, dropout)
        self.payload_graphConv = GraphSAGEEncoder(embedding_size, h_feats, dropout)
        self.payload_mode = payload_mode

    def forward(self, header_batch, payload_batch, labels):
        batch_size = labels.shape[0]
        if self.payload_mode == 'payload-only':
            p = self.payload_graphConv(payload_batch.x, payload_batch.edge_index, payload_batch.batch)
            p = p.reshape(batch_size, 50, -1)
            h = torch.zeros_like(p)
        else:
            h = self.header_graphConv(header_batch.x, header_batch.edge_index, header_batch.batch)
            h = h.reshape(batch_size, 50, -1)
            if self.payload_mode == 'header-only':
                p = torch.zeros_like(h)
            else:
                p = self.payload_graphConv(payload_batch.x, payload_batch.edge_index, payload_batch.batch)
                p = p.reshape(batch_size, 50, -1)
        fused = self.gated_filter(h, p)
        _, (hidden, _) = self.rnn(fused)
        return self.cls(self.fc(torch.cat((hidden[-1], hidden[-2]), dim=1)))

# Compatibility names share the canonical implementation and state-dict keys.
GCN_PyG = GraphSAGEEncoder
Cross_Gated_Info_Filter = CrossGatedInfoFilter
MixTemporalGNN_PyG = TFEGNN
