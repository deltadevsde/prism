#!/usr/bin/env python3
"""
Upload AST data to Modal volume
"""

import modal
import os
from pathlib import Path

app = modal.App("prism-data-upload")
volume = modal.Volume.from_name("prism-kg-data", create_if_missing=True)

@app.function(volumes={"/data": volume}, timeout=1200)
def upload_files(file_data: dict):
    """Upload files to Modal volume"""
    
    # Create ast_output directory
    os.makedirs("/data/ast_output", exist_ok=True)
    
    # Write each file
    for filename, content in file_data.items():
        file_path = f"/data/ast_output/{filename}"
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Uploaded: {filename}")
    
    # Commit volume changes
    volume.commit()
    
    return f"Uploaded {len(file_data)} files successfully"

@app.local_entrypoint()
def main():
    """Upload all AST files to Modal"""
    
    ast_dir = Path("ast_output")
    if not ast_dir.exists():
        print("Error: ast_output directory not found!")
        return
    
    # Read all JSON-LD files
    file_data = {}
    for file_path in ast_dir.glob("*.jsonld"):
        try:
            with open(file_path, 'r') as f:
                file_data[file_path.name] = f.read()
            print(f"Loaded: {file_path.name}")
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    if not file_data:
        print("No JSON-LD files found to upload!")
        return
    
    print(f"Found {len(file_data)} files to upload...")
    
    # Upload to Modal
    result = upload_files.remote(file_data)
    print(f"Upload result: {result}")

if __name__ == "__main__":
    main()