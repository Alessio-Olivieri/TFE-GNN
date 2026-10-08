"""Restore original TFE-GNN semantics using the recovered student's PyG model.

Original src/model.py is deliberately preserved. Fusion/LSTM/classifier are
inherited. No CLE-TFE components are used. See RECOVERY_REPORT.md for provenance.
"""
import math
import sys
from pathlib import Path

import torch
from torch import nn

from tests.fixtures.base_model import GCN_PyG, MixTemporalGNN_PyG


class OriginalSemanticsEncoder(GCN_PyG):
    def __init__(self, embedding_size, h_feats, dropout):
        super().__init__(embedding_size, h_feats, dropout)
        # DGL SAGEConv uses Glorot weights with ReLU gain, unlike PyG's default.
        # PyG's neighbor bias plus bias-free root is algebraically the same
        # single bias as DGL's bias-free neighbor plus biased root.
        for layer in (self.gcn1, self.gcn2, self.gcn3, self.gcn4):
            nn.init.xavier_uniform_(layer.lin_l.weight, gain=math.sqrt(2))
            nn.init.xavier_uniform_(layer.lin_r.weight, gain=math.sqrt(2))
            bound = 1 / math.sqrt(layer.lin_l.in_channels)
            nn.init.uniform_(layer.lin_l.bias, -bound, bound)

    def forward(self, x, edge_index, batch):
        from torch_geometric.nn import global_mean_pool
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


class RecoveredTFEGNN(MixTemporalGNN_PyG):
    def __init__(self, payload_mode='real'):
        super().__init__(num_classes=6, embedding_size=64, h_feats=128,
                         dropout=0.2, downstream_dropout=0.0)
        self.header_graphConv = OriginalSemanticsEncoder(64, 128, 0.2)
        self.payload_graphConv = OriginalSemanticsEncoder(64, 128, 0.2)
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
