import os
import json
import gzip

RAW_DIR = "./data_seeds"
PARSED_DIR = "./parsed_feeds"

def remove_noise_and_parse():
    print(f"[INFO] Starting noise removal from {RAW_DIR}...")

    if not os.path.exists(PARSED_DIR):
        os.makedirs(PARSED_DIR)
        print(f"[INFO] Created folder: {PARSED_DIR}")

    files = [f for f in os.listdir(RAW_DIR) if f.endswith(".json.gz")]
    print(f"[INFO] Found {len(files)} compressed JSON files in {RAW_DIR}: {files}")

    for file_name in files:
        file_path = os.path.join(RAW_DIR, file_name)

        print(f"[INFO] Processing {file_name}...")

        with gzip.open(file_path, "rt", encoding="utf-8") as f:
            data = json.load(f)

        cleaned_cves = []

        # Parse based on known NVD structure
        cve_items = data.get("CVE_Items") or data.get("vulnerabilities", [])

        for item in cve_items:
            cve = item.get("cve", {})
            cve_id = cve.get("CVE_data_meta", {}).get("ID")
            descriptions = cve.get("description", {}).get("description_data", [])
            description = descriptions[0].get("value") if descriptions else ""

            # ❌ Skip noisy or placeholder CVEs
            if (
                not description
                or "DO NOT USE THIS CANDIDATE NUMBER" in description.upper()
                or "REJECT" in description.upper()
            ):
                continue

            # Severity & score
            severity = None
            score = None
            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
                score = impact["baseMetricV3"]["cvssV3"]["baseScore"]

            cleaned_cves.append({
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "score": score,
                "published_date": item.get("publishedDate")
            })

        # Write cleaned JSON
        output_file_name = file_name.replace(".json.gz", "_parsed.json")
        output_path = os.path.join(PARSED_DIR, output_file_name)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cleaned_cves, f, indent=2)

        print(f"[INFO] ✅ Saved cleaned data to {output_path} with {len(cleaned_cves)} valid CVE entries.")

if __name__ == "__main__":
    remove_noise_and_parse()
    print("[INFO] 🎉 Noise removal and parse completed.")
