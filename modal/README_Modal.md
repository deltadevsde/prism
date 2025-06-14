# Modal Training Setup for Prism Knowledge Graph

This setup enables training ML models on the Prism AST knowledge graph using Modal's cloud infrastructure.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Authenticate with Modal:**
   ```bash
   modal token new
   ```

3. **Setup infrastructure:**
   ```bash
   python setup_modal.py
   ```

4. **Upload AST data:**
   ```bash
   python upload_data.py
   ```

5. **Start training:**
   ```bash
   modal run modal_training.py
   ```

## Files Overview

- `modal_training.py` - Main training pipeline with GPU support
- `setup_modal.py` - Infrastructure setup script  
- `upload_data.py` - Data upload utility
- `requirements.txt` - Python dependencies

## Training Features

- **GPU Support**: Uses A10G GPUs for training
- **Knowledge Graph Processing**: Converts JSON-LD to embeddings
- **Persistent Storage**: Modal volumes for data persistence
- **Scalable**: Automatic retries and timeout handling

## Customization

Modify the `config` dictionary in `modal_training.py` to adjust:
- Batch size
- Learning rate  
- Number of epochs
- Model architecture

## Data Structure

The knowledge graph contains:
- 21 JSON-LD files (2.6MB total)
- Rust AST nodes and relationships
- Cross-references between code elements
- Metadata about functions, types, and modules