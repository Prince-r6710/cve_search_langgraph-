# scripts/download_nvd_feeds.py

import os
import requests
from tqdm import tqdm

def download_file(url, dest_path):
    response = requests.get(url, stream=True)
    total = int(response.headers.get('content-length', 0))
    with open(dest_path, 'wb') as file, tqdm(
        desc=dest_path,
        total=total,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in response.iter_content(chunk_size=1024):
            size = file.write(data)
            bar.update(size)

if __name__ == "__main__":
    os.makedirs("data_feeds", exist_ok=True)

    years = range(2002, 2025)  # Adjust as needed
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/"

    for year in years:
        file_name = f"nvdcve-1.1-{year}.json.gz"
        url = base_url + file_name
        dest_path = os.path.join("data_feeds", file_name)

        print(f"Downloading {file_name}...")
        download_file(url, dest_path)

    print("✅ All files downloaded.")
