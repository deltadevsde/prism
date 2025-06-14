#!/usr/bin/env python3
"""
Setup script for Modal training infrastructure
"""

import os
import shutil
import modal
from pathlib import Path

# Create Modal app for setup
app = modal.App("prism-kg-setup")

# Volume for data storage
volume = modal.Volume.from_name("prism-kg-data", create_if_missing=True)

@app.function(volumes={"/data": volume}, timeout=600)
def upload_ast_data():
    """Upload AST output data to Modal volume"""
    
    # Create directory structure in volume
    os.makedirs("/data/ast_output", exist_ok=True)
    
    # In a real setup, you'd upload the files here
    # For now, we'll create a placeholder
    with open("/data/setup_complete.txt", "w") as f:
        f.write("Modal volume setup completed\n")
    
    print("AST data directory created in Modal volume")
    return "Setup complete"

@app.local_entrypoint()
def setup():
    """Setup Modal infrastructure"""
    
    print("Setting up Modal infrastructure for Prism KG training...")
    
    # Create volume and upload data
    result = upload_ast_data.remote()
    print(f"Setup result: {result}")
    
    print("\nTo upload your AST data:")
    print("1. Install Modal CLI: pip install modal")
    print("2. Authenticate: modal token new")
    print("3. Upload data using Modal CLI or the upload script")
    
    print("\nNext steps:")
    print("1. Run: python upload_data.py (to upload AST files)")
    print("2. Run: modal run modal_training.py (to start training)")

if __name__ == "__main__":
    setup()