import os
import sys

# Windows terminal encoding fix for piped outputs
sys.stdout.reconfigure(encoding='utf-8')

import pandas as pd
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from masking.pii_masker import PIIMasker

def run_excel_benchmark(file_path: str):
    """
    Reads the given Excel file, processes each row to detect PHI/PII,
    and prints the detection results.
    """
    print("=" * 80)
    print(f"  HEALTHCARE PRIVACY FIREWALL — EXCEL DATASET BENCHMARK")
    print(f"  File: {file_path}")
    print("=" * 80)
    print()

    if not os.path.exists(file_path):
        print(f"❌ Error: Excel file not found at {file_path}")
        return

    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        print(f"❌ Error reading Excel file: {e}")
        return

    masker = PIIMasker()
    
    total_rows = len(df)
    total_entities_found = 0
    high_risk_rows = 0

    for index, row in df.iterrows():
        # Combine the row data into a single text payload for scanning
        row_text_parts = []
        for col_name, value in row.items():
            if pd.notna(value):
                row_text_parts.append(f"{col_name}: {value}")
        
        combined_text = " | ".join(row_text_parts)
        
        # Process the text
        result = masker.process_text(combined_text)
        
        # Extract metrics
        entities_found = result.get("entity_count", 0)
        risk_level = result.get("risk", {}).get("level", "low")
        detections = result.get("detections", [])
        
        total_entities_found += entities_found
        if risk_level in ["high", "critical"]:
            high_risk_rows += 1
            
        # Print row results
        status = "[CRITICAL]" if risk_level == "critical" else (
                 "[HIGH]    " if risk_level == "high" else
                 "[MEDIUM]  " if risk_level == "medium" else
                 "[LOW]     " )
                 
        print(f"Row {index + 1:03d} {status} | Found {entities_found:2d} entities")
        
        if entities_found > 0:
            found_types = {}
            for d in detections:
                etype = d["entity_type"]
                found_types[etype] = found_types.get(etype, 0) + 1
            
            print(f"           └─ Types: {', '.join([f'{k}({v})' for k,v in found_types.items()])}")
            
    print("\n" + "=" * 80)
    print("  RESULTS SUMMARY")
    print("=" * 80)
    print(f"  Total Rows Processed:   {total_rows}")
    print(f"  Total Entities Found:   {total_entities_found}")
    print(f"  High/Critical Risk Rows:{high_risk_rows}")
    print("================================================================================")


if __name__ == "__main__":
    dataset_path = r"c:\Users\pc\Downloads\Healthcare Privacy Firewall\pii_phi_test_dataset.xlsx"
    run_excel_benchmark(dataset_path)
