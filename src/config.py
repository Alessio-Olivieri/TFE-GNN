"""Compatibility constants for the original graph-constructor boundary.

Validated training settings are declared in src.train and the experiment guide.
"""
import torch
'''
Training Configuration
'''
class Config:
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    BATCH_SIZE = 102
    GRADIENT_ACCUMULATION = 5
    MAX_EPOCH = 20
    LR = 1e-2
    LR_MIN = 1e-4
    LABEL_SMOOTHING = 0
    WEIGHT_DECAY = 0
    WARM_UP = 0.1
    SEED = 32
    DROPOUT = 0.2
    DOWNSTREAM_DROPOUT = 0.0

    EMBEDDING_SIZE = 64
    H_FEATS = 128
    NUM_CLASSES = 14

    PMI_WINDOW_SIZE = 5
    PAD_TRUNC_DIGIT = 256
    FLOW_PAD_TRUNC_LENGTH = 50
    BYTE_PAD_TRUNC_LENGTH = 150
    HEADER_MAX_LEN = 40 # HEADER_BYTE_PAD_TRUNC_LENGTH
    ANOMALOUS_FLOW_THRESHOLD = 10000

    PAD_BYTES = True  

if __name__ == '__main__':
    config = Config()