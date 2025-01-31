import pandas as pd
import requests
import io
import os

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
    
    # Select relevant columns and drop rows with missing values
    df_filtered = df[["guid", "metadata_description", "metadata_link"]].dropna()
    
    # Generate the YARA rule
    yara_rule = """
rule GUID_Detection
{
    meta:
        author = "@mthcht"
        description = "Detects GUIDs of offensive tools - taken from https://github.com/BADGUIDS/badguids.github.io"
    
    strings:
"""
    
    # Add GUIDs with comments
    for _, row in df_filtered.iterrows():
        guid = row["guid"]
        description = row["metadata_description"]
        link = row["metadata_link"]
        
        yara_rule += f'        // {description}\n'
        yara_rule += f'        // {link}\n'
        yara_rule += f'        $guid_{guid.replace("-", "_")} = "{guid}" nocase\n\n'
    
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

# Define the output path in a cross-platform way
output_yara_path = os.path.join("..", "yara_rules", "guids_only.yara")

# Example usage
generate_yara_from_csv(
    "https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/refs/heads/main/GUIDproject_tag_detection.csv",
    output_yara_path
)
