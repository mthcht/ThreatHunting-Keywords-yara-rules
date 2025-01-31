import pandas as pd
import requests
import io
import os
import struct

def guid_to_binary(guid):
    """Convert GUID string to binary representation (little-endian format)."""
    parts = guid.split('-')
    if len(parts) != 5:
        raise ValueError(f"Invalid GUID format: {guid}")

    # Convert each part to little-endian byte order
    d1 = struct.pack('<I', int(parts[0], 16))
    d2 = struct.pack('<H', int(parts[1], 16))
    d3 = struct.pack('<H', int(parts[2], 16))
    d4 = bytes.fromhex(parts[3])
    d5 = bytes.fromhex(parts[4])

    # Return binary format as a space-separated hex string
    return ' '.join(f"{b:02X}" for b in (d1 + d2 + d3 + d4 + d5))

def generate_yara_from_csv(csv_url, output_yara_file):
    # Fetch the CSV file from the URL
    response = requests.get(csv_url)
    response.raise_for_status()
    
    # Load the CSV file into a DataFrame
    df = pd.read_csv(io.StringIO(response.text))
    
    # Ensure necessary columns exist
    required_columns = ["keyword", "metadata_description", "metadata_link"]
    if not all(col in df.columns for col in required_columns):
        raise ValueError("CSV file must contain 'keyword', 'metadata_description', and 'metadata_link' columns.")
    
    # Extract and clean GUIDs by removing wildcards (*)
    df["guid"] = df["keyword"].str.strip("*")
    
    # Remove duplicates
    df_filtered = df[["guid", "metadata_description", "metadata_link"]].dropna().drop_duplicates(subset=["guid"])
    
    # Generate the YARA rule
    yara_rule = """
rule GUID_Detection
{
    meta:
        author = "@mthcht"
        description = "Detects GUIDs of offensive tools - https://github.com/BADGUIDS/badguids.github.io"
    
    strings:
"""
    
    # Add GUIDs with comments and binary representation
    for _, row in df_filtered.iterrows():
        guid = row["guid"]
        description = row["metadata_description"]
        link = row["metadata_link"]
        guid_id = guid.replace("-", "_")
        binary_guid = guid_to_binary(guid)
        
        yara_rule += f'        // {description}\n'
        yara_rule += f'        // {link}\n'
        yara_rule += f'        $guid_{guid_id}_str = "{guid}" ascii wide nocase\n'
        yara_rule += f'        $guid_{guid_id}_bin = {{ {binary_guid} }}\n\n'
    
    yara_rule += """
    condition:
        any of them
}
"""
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_yara_file), exist_ok=True)

    # Save the YARA rule to a file
    with open(output_yara_file, "w") as f:
        f.write(yara_rule)
    
    print(f"YARA rule file generated: {output_yara_file}")

output_yara_path = os.path.join("..", "yara_rules", "guids_only.yara")

generate_yara_from_csv(
    "https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/refs/heads/main/GUIDproject_tag_detection.csv",
    output_yara_path
)
