import os
import csv
from collections import defaultdict
import re

# List of YARA reserved keywords
yara_reserved_keywords = {
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition",
    "contains", "endswith", "entrypoint", "false", "filesize", "for", "fullword",
    "global", "import", "icontains", "iendswith", "iequals", "in", "include", "int16",
    "int16be", "int32", "int32be", "int8", "int8be", "istartswith", "matches", "meta",
    "nocase", "none", "not", "of", "or", "private", "rule", "startswith", "strings",
    "them", "true", "uint16", "uint16be", "uint32", "uint32be", "uint8", "uint8be",
    "wide", "xor", "defined"
}

def get_subdirectory_name(tool):
    first_letter = tool[0].upper()
    if not first_letter.isalpha():
        return "_Others"
    mapping = {
        "A" : "A-C", "B" : "A-C", "C" : "A-C",
        "D" : "D-F", "E" : "D-F", "F" : "D-F",
        "G" : "G-H", "H" : "G-H",
        "I" : "I-K", "J" : "I-K", "K" : "I-K",
        "L" : "L-N", "M" : "L-N", "N" : "L-N",
        "O" : "O-Q", "P" : "O-Q", "Q" : "O-Q",
        "R" : "R-T", "S" : "R-T", "T" : "R-T",
        "U" : "U-W", "V" : "U-W", "W" : "U-W",
        "X" : "X-Z", "Y" : "X-Z", "Z" : "X-Z"
    }
    return mapping.get(first_letter, "_Others")

def safe_tool_name(tool):
    sanitized_tool = tool
    if tool[0].isdigit() or tool.lower() in yara_reserved_keywords:
        sanitized_tool = f"_{tool}"
    return (sanitized_tool.replace('-', '_')
                          .replace(' ', '_')
                          .replace('.', '_')
                          .replace('&', '_and_')
                          .replace('$', '')
                          .replace('(', '_')
                          .replace(')', '_'))

def clean_all_letter_directories(base_directory):
    for category in os.listdir(base_directory):
        category_path = os.path.join(base_directory, category)
        if os.path.isdir(category_path):
            for subdirectory in os.listdir(category_path):
                subdirectory_path = os.path.join(category_path, subdirectory)
                if os.path.isdir(subdirectory_path):
                    for filename in os.listdir(subdirectory_path):
                        file_path = os.path.join(subdirectory_path, filename)
                        if os.path.isfile(file_path):
                            os.remove(file_path)

def generate_yara_rules(base_directory):
    script_directory = os.path.dirname(os.path.realpath(__file__))
    csv_file_path = os.path.join(script_directory, 'threathunting-keywords.csv')
    base_directory = os.path.join(script_directory, base_directory)
    
    clean_all_letter_directories(base_directory)
    
    aggregated_data = defaultdict(list)
    
    with open(csv_file_path, 'r', newline='') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            tool = row['metadata_tool']
            keyword = row['keyword']
            description = row['metadata_description']
            reference = row['metadata_link']
            keyword_type = row['metadata_keyword_type']
            metadata_tags = row.get('metadata_tags', "")
            # New fallback field
            keyword_regex = row.get('metadata_keyword_regex', "")

            aggregated_data[(tool, keyword_type)].append(
                (keyword, description, reference, metadata_tags, keyword_regex)
            )
    
    if not os.path.exists(base_directory):
        os.makedirs(base_directory)
        
    for (tool, keyword_type), items in aggregated_data.items():
        keyword_type_dir = os.path.join(base_directory, keyword_type)
        subdirectory_name = get_subdirectory_name(tool)
        final_directory = os.path.join(keyword_type_dir, subdirectory_name)
        
        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

        sanitized_tool = safe_tool_name(tool)
        
        with open(os.path.join(final_directory, f"{tool}.yara"), 'w') as outfile:
            outfile.write(f"rule {sanitized_tool}\n")
            outfile.write("{\n")
            outfile.write("    meta:\n")
            outfile.write(f"        description = \"Detection patterns for the tool '{tool}' taken from the ThreatHunting-Keywords github project\"\n")
            outfile.write(f"        author = \"@mthcht\"\n")
            outfile.write(f"        reference = \"https://github.com/mthcht/ThreatHunting-Keywords\"\n")
            outfile.write(f"        tool = \"{tool}\"\n")
            outfile.write(f"        rule_category = \"{keyword_type}\"\n")
            outfile.write("\n    strings:\n")
            
            for idx, (keyword, description, reference, metadata_tags, keyword_regex) in enumerate(items):
                description_sanitized = description.replace("\n", " ")
                outfile.write(f"        // Description: {description_sanitized}\n")
                outfile.write(f"        // Reference: {reference}\n")

                if not keyword.strip():
                    # If 'keyword' is empty, use the raw regex from 'metadata_keyword_regex'
                    actual_keyword = keyword_regex
                    is_regex = True
                else:
                    actual_keyword = keyword.strip('*')
                    # Check if it contains wildcard or special chars
                    is_regex = bool(re.search(r'[.^$+?{}\[\]\\|()*]', actual_keyword))

                # Decide whether to include modifiers
                if "#linux" in metadata_tags.lower():
                    modifiers = ""
                else:
                    modifiers = " nocase ascii wide"

                if is_regex and keyword.strip():
                    # 'keyword' is not empty but has special chars => escape
                    escaped_keyword = (actual_keyword.replace("\\", "\\\\")
                                                  .replace("\"", "\\\"")
                                                  .replace(" ", r"\s")
                                                  .replace("|", r"\|")
                                                  .replace("/", r"\/")
                                                  .replace(".", r"\.")
                                                  .replace("(", r"\(")
                                                  .replace(")", r"\)")
                                                  .replace('+', r"\+")
                                                  .replace("&", r"\&")
                                                  .replace('?', r"\?")
                                                  .replace('[', r"\[")
                                                  .replace(']', r"\]")
                                                  .replace("'", r"\'")
                                                  .replace('-', r"\-")
                                                  .replace('!', r"\!")
                                                  .replace('#', r"\#")
                                                  .replace('"', r"\"")
                                                  .replace('^', r"\^")
                                                  .replace('%', r"\%")
                                                  .replace('=', r"\=")
                                                  .replace('$', r"\$")
                                                  .replace(';', r"\;")
                                                  .replace('<', r"\<")
                                                  .replace('>', r"\>")
                                                  .replace('@', r"\@")
                                                  .replace('}', r"\}")
                                                  .replace('{', r"\{")
                                                  .replace(',', r"\,")
                                                  .replace('`', r"\`")
                                                  .replace('~', r"\~")
                                                  .replace(':', r"\:")
                                                  .replace('*', '.{0,1000}'))
                    outfile.write(f"        $string{idx+1} = /{escaped_keyword}/{modifiers}\n")

                elif is_regex and not keyword.strip():
                    # 'keyword' is empty, so we rely purely on 'metadata_keyword_regex'
                    outfile.write(f"        $string{idx+1} = /{actual_keyword}/{modifiers}\n")

                else:
                    # Normal string
                    escaped_keyword = (actual_keyword
                                       .replace("\\", "\\\\")
                                       .replace("\"", "\\\""))
                    outfile.write(f"        $string{idx+1} = \"{escaped_keyword}\"{modifiers}\n")
                
            outfile.write("\n    condition:\n")
            outfile.write("        any of them\n")
            outfile.write("}\n")

if __name__ == "__main__":
    output_directory = os.path.join('..', 'yara_rules')
    generate_yara_rules(output_directory)
