#!/usr/bin/env python3
"""
Modal training infrastructure for Prism knowledge graph
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import modal

# Define Modal app
app = modal.App("prism-kg-training")

# Define the image with required dependencies
image = modal.Image.debian_slim().pip_install([
    "torch",
    "transformers",
    "datasets",
    "accelerate",
    "wandb",
    "rdflib",
    "pyld",
    "numpy",
    "scikit-learn",
    "sentence-transformers",
    "faiss-cpu"
])

# Create volume for persistent storage
volume = modal.Volume.from_name("prism-kg-data", create_if_missing=True)

@app.function(
    image=image,
    volumes={"/data": volume},
    gpu="A10G",
    timeout=3600,
    retries=2
)
def process_knowledge_graph(kg_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process and prepare knowledge graph data for training"""
    
    import torch
    from sentence_transformers import SentenceTransformer
    import numpy as np
    
    # Initialize embedding model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Extract nodes and edges from knowledge graph
    nodes = kg_data.get('nodes', [])
    edges = kg_data.get('edges', [])
    
    # Prepare node embeddings
    node_texts = []
    node_ids = []
    
    for node in nodes:
        # Create text representation of each node
        text = f"{node.get('label', '')} {node.get('@type', '')} {node.get('crate_name', '')}"
        node_texts.append(text.strip())
        node_ids.append(node.get('@id', ''))
    
    # Generate embeddings
    embeddings = model.encode(node_texts)
    
    # Create training data structure
    training_data = {
        'node_embeddings': embeddings.tolist(),
        'node_ids': node_ids,
        'edges': edges,
        'num_nodes': len(nodes),
        'num_edges': len(edges)
    }
    
    return training_data

@app.function(
    image=image,
    volumes={"/data": volume},
    gpu="A10G",
    timeout=7200,
    retries=2
)
def train_kg_model(training_data: List[Dict[str, Any]], config: Dict[str, Any]) -> str:
    """Train a model on the knowledge graph data"""
    
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    import numpy as np
    
    class KGDataset(Dataset):
        def __init__(self, embeddings, edges):
            self.embeddings = torch.FloatTensor(embeddings)
            self.edges = edges
            
        def __len__(self):
            return len(self.edges)
            
        def __getitem__(self, idx):
            edge = self.edges[idx]
            # Simple implementation - could be enhanced based on specific needs
            return {
                'source': edge.get('source', ''),
                'target': edge.get('target', ''),
                'edge_type': edge.get('edge_type', '')
            }
    
    # Combine all training data
    all_embeddings = []
    all_edges = []
    
    for data in training_data:
        all_embeddings.extend(data['node_embeddings'])
        all_edges.extend(data['edges'])
    
    # Create dataset and dataloader
    dataset = KGDataset(all_embeddings, all_edges)
    dataloader = DataLoader(dataset, batch_size=config.get('batch_size', 32), shuffle=True)
    
    # Simple neural network for demonstration
    class SimpleKGModel(nn.Module):
        def __init__(self, embedding_dim=384, hidden_dim=256):
            super().__init__()
            self.fc1 = nn.Linear(embedding_dim, hidden_dim)
            self.fc2 = nn.Linear(hidden_dim, hidden_dim)
            self.fc3 = nn.Linear(hidden_dim, embedding_dim)
            self.relu = nn.ReLU()
            self.dropout = nn.Dropout(0.1)
            
        def forward(self, x):
            x = self.relu(self.fc1(x))
            x = self.dropout(x)
            x = self.relu(self.fc2(x))
            x = self.dropout(x)
            x = self.fc3(x)
            return x
    
    model = SimpleKGModel()
    optimizer = torch.optim.Adam(model.parameters(), lr=config.get('learning_rate', 0.001))
    criterion = nn.MSELoss()
    
    # Training loop
    model.train()
    for epoch in range(config.get('epochs', 10)):
        total_loss = 0
        for batch_idx, batch in enumerate(dataloader):
            # Simple training step - enhance based on specific objectives
            optimizer.zero_grad()
            
            # For demonstration, we'll do a simple autoencoder task
            # In practice, you'd define specific objectives based on your needs
            dummy_input = torch.randn(len(batch['source']), 384)
            output = model(dummy_input)
            loss = criterion(output, dummy_input)
            
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        avg_loss = total_loss / len(dataloader)
        print(f"Epoch {epoch+1}/{config.get('epochs', 10)}, Average Loss: {avg_loss:.4f}")
    
    # Save model
    model_path = "/data/kg_model.pth"
    torch.save(model.state_dict(), model_path)
    
    return f"Model trained and saved to {model_path}"

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=1800
)
def load_and_preprocess_ast_data() -> List[Dict[str, Any]]:
    """Load and preprocess AST JSON-LD files"""
    
    import json
    from pathlib import Path
    
    # This would be called with the AST data uploaded to the volume
    ast_files = list(Path("/data/ast_output").glob("*.jsonld"))
    processed_data = []
    
    for file_path in ast_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                processed_data.append(data)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    return processed_data

@app.local_entrypoint()
def main():
    """Main training pipeline"""
    
    print("Starting Prism Knowledge Graph training pipeline...")
    
    # Configuration
    config = {
        'batch_size': 32,
        'learning_rate': 0.001,
        'epochs': 20,
        'model_type': 'simple_kg'
    }
    
    # Load and preprocess data
    print("Loading AST data...")
    ast_data = load_and_preprocess_ast_data.remote()
    
    # Process knowledge graph data
    print("Processing knowledge graph...")
    training_data = []
    for data in ast_data:
        processed = process_knowledge_graph.remote(data)
        training_data.append(processed)
    
    # Train model
    print("Training model...")
    result = train_kg_model.remote(training_data, config)
    
    print(f"Training completed: {result}")

if __name__ == "__main__":
    main()