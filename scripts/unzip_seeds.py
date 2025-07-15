# utils/unzip_feeds.py

import os
import gzip
import shutil

def unzip_all_files(source_dir="./data_seeds", target_dir="./parsed_feeds"):
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    files = [f for f in os.listdir(source_dir) if f.endswith(".json.gz")]
    print(f"[INFO] Found {len(files)} .json.gz files to unzip.")
    
    for file_name in files:
        source_path = os.path.join(source_dir, file_name)
        target_file = file_name.replace(".json.gz", ".json")
        target_path = os.path.join(target_dir, target_file)
        
        with gzip.open(source_path, 'rb') as f_in:
            with open(target_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        print(f"[INFO] Unzipped {file_name} -> {target_file}")

if __name__ == "__main__":
    unzip_all_files()
