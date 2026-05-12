import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import classification_report

from dataset import TrafficFlowDataset, pyg_collate_fn
from model import MixTemporalGNN_PyG  
from torch.optim import GradualWarmupScheduler
from config import Config as cfg

def evaluate(model, dataloader):
    model.eval()
    all_preds = []
    all_labels =[]
    
    with torch.no_grad():
        for header_batch, payload_batch, labels in dataloader:
            header_batch = header_batch.to(cfg.DEVICE)
            payload_batch = payload_batch.to(cfg.DEVICE)
            
            logits = model(header_batch, payload_batch, labels)
            preds = logits.argmax(dim=1).cpu().numpy()
            
            all_preds.extend(preds)
            all_labels.extend(labels.numpy())
            
    # Calculate metrics
    report = classification_report(all_labels, all_preds, digits=4, zero_division=0)
    return report

def train():
    print(f"Using device: {cfg.DEVICE}")
    
    # 1. Load Data
    train_dataset = TrafficFlowDataset('data/train_headers.pt', 'data/train_payloads.pt', 'data/train_labels.pt')
    test_dataset = TrafficFlowDataset('data/test_headers.pt', 'data/test_payloads.pt', 'data/test_labels.pt')
    
    train_loader = DataLoader(train_dataset, batch_size=cfg.BATCH_SIZE, shuffle=True, collate_fn=pyg_collate_fn, num_workers=4, pin_memory=True)
    test_loader = DataLoader(test_dataset, batch_size=cfg.BATCH_SIZE, shuffle=False, collate_fn=pyg_collate_fn, num_workers=4, pin_memory=True)
    
    # 2. Initialize Model
    model = MixTemporalGNN_PyG(num_classes=cfg.NUM_CLASSES).to(cfg.DEVICE)
    
    # 3. Optimizers & Schedulers
    optimizer = torch.optim.Adam(model.parameters(), lr=cfg.LR, weight_decay=cfg.WEIGHT_DECAY)
    
    total_steps = len(train_loader) * cfg.MAX_EPOCH
    warmup_steps = int(total_steps * cfg.WARM_UP_RATIO)
    
    after_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=(total_steps - warmup_steps), eta_min=cfg.LR_MIN
    )
    scheduler = GradualWarmupScheduler(optimizer, warmup_iter=warmup_steps, after_scheduler=after_scheduler)
    
    criterion = nn.CrossEntropyLoss(label_smoothing=cfg.LABEL_SMOOTHING)
    
    # 4. Training Loop
    best_f1 = 0.0
    
    for epoch in range(1, cfg.MAX_EPOCH + 1):
        model.train()
        total_loss = 0
        correct = 0
        total_samples = 0
        
        for batch_idx, (header_batch, payload_batch, labels) in enumerate(train_loader):
            header_batch = header_batch.to(cfg.DEVICE)
            payload_batch = payload_batch.to(cfg.DEVICE)
            labels = labels.to(cfg.DEVICE)
            
            optimizer.zero_grad()
            
            # Forward pass
            logits = model(header_batch, payload_batch, labels)
            loss = criterion(logits, labels)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            scheduler.step()
            
            # Metrics
            total_loss += loss.item()
            preds = logits.argmax(dim=1)
            correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            if batch_idx % 50 == 0:
                print(f"Epoch [{epoch}/{cfg.MAX_EPOCH}] Batch [{batch_idx}/{len(train_loader)}] Loss: {loss.item():.4f} cfg.LR: {optimizer.param_groups[0]['lr']:.6f}")
                
        train_acc = correct / total_samples
        print(f"=== Epoch {epoch} Summary ===")
        print(f"Train Loss: {total_loss/len(train_loader):.4f} | Train Acc: {train_acc:.4f}")
        
        # 5. Evaluate at the end of every epoch
        print("Evaluating on Test Set...")
        report = evaluate(model, test_loader)
        print(report)
        
        # Save checkpoint
        torch.save(model.state_dict(), f"checkpoint_epoch_{epoch}.pth")

if __name__ == "__main__":
    train()