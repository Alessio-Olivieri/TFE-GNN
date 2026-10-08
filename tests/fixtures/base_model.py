import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv, global_mean_pool

FLOW_PAD_TRUNC_LENGTH = 50

class GCN_PyG(nn.Module):
    def __init__(self, embedding_size, h_feats, dropout):
        super(GCN_PyG, self).__init__()
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

    def forward(self, x, edge_index, batch):
        # x is shape [Total_Nodes_in_Batch, 1]. View(-1) flattens it for embedding
        h = self.embedding(x.long().view(-1)) 
        
        h1 = self.dropout(self.act1(self.bn1(self.gcn1(h, edge_index))))
        h2 = self.dropout(self.act2(self.bn2(self.gcn2(h1, edge_index))))
        h3 = self.dropout(self.act3(self.bn3(self.gcn3(h2, edge_index))))
        h4 = self.act4(self.bn4(self.gcn4(h3, edge_index)))
        
        # Jumping Knowledge Network: Concatenate all layer outputs
        h_concat = torch.cat((h1, h2, h3, h4), dim=1)
        
        # Graph-level Readout (Equivalent to dgl.mean_nodes)
        g_vec = global_mean_pool(h_concat, batch)
        
        return g_vec

class Cross_Gated_Info_Filter(nn.Module):
    # (Unchanged from original code)
    def __init__(self, in_size):
        super(Cross_Gated_Info_Filter, self).__init__()
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

class MixTemporalGNN_PyG(nn.Module):
    def __init__(self, num_classes, embedding_size=64, h_feats=128, dropout=0.2, downstream_dropout=0.0):
        super(MixTemporalGNN_PyG, self).__init__()
        self.header_graphConv = GCN_PyG(embedding_size, h_feats, dropout)
        self.payload_graphConv = GCN_PyG(embedding_size, h_feats, dropout)
        
        self.gcn_out_dim = 4 * h_feats
        self.gated_filter = Cross_Gated_Info_Filter(in_size=self.gcn_out_dim)
        self.rnn = nn.LSTM(input_size=self.gcn_out_dim * 2, hidden_size=self.gcn_out_dim * 2, 
                           num_layers=2, bidirectional=True, dropout=downstream_dropout, batch_first=True)
        self.fc = nn.Sequential(
            nn.Linear(in_features=self.gcn_out_dim * 4, out_features=self.gcn_out_dim),
            nn.PReLU(self.gcn_out_dim)
        )
        self.cls = nn.Linear(in_features=self.gcn_out_dim, out_features=num_classes)

    def forward(self, header_batch, payload_batch, labels):
        # 1. Apply Graph Convolution
        header_gcn_out = self.header_graphConv(header_batch.x, header_batch.edge_index, header_batch.batch)
        payload_gcn_out = self.payload_graphConv(payload_batch.x, payload_batch.edge_index, payload_batch.batch)
        
        # 2. Reshape from (Batch_Size * 50, Hidden_Dim) to (Batch_Size, 50, Hidden_Dim)
        batch_size = labels.shape[0]
        header_gcn_out = header_gcn_out.reshape(batch_size, FLOW_PAD_TRUNC_LENGTH, -1)
        payload_gcn_out = payload_gcn_out.reshape(batch_size, FLOW_PAD_TRUNC_LENGTH, -1)
        
        # 3. Apply Cross-Gated Filter
        gcn_out = self.gated_filter(header_gcn_out, payload_gcn_out)
        
        # 4. LSTM sequence modeling (Using batch_first=True makes this cleaner)
        _, (h_n, _) = self.rnn(gcn_out)
        rnn_out = torch.cat((h_n[-1], h_n[-2]), dim=1) # Get the last bidirectional states
        
        out = self.fc(rnn_out)
        out = self.cls(out)
        return out