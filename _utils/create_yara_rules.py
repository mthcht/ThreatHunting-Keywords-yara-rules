import os
import csv
from collections import defaultdict
import re

# List of YARA reserved keywords
yara_reserved_keywords = set([
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition",
    "contains", "endswith", "entrypoint", "false", "filesize", "for", "fullword",
    "global", "import", "icontains", "iendswith", "iequals", "in", "include", "int16",
    "int16be", "int32", "int32be", "int8", "int8be", "istartswith", "matches", "meta",
    "nocase", "none", "not", "of", "or", "private", "rule", "startswith", "strings",
    "them", "true", "uint16", "uint16be", "uint32", "uint32be", "uint8", "uint8be",
    "wide", "xor", "defined"
])

def get_subdirectory_name(tool):
    first_letter = tool[0].upper()
    if not first_letter.isalpha():
        return "_Others"
    mapping = {
        "A": "A-C",
        "B": "A-C",
        "C": "A-C",
        "D": "D-F",
        "E": "D-F",
        "F": "D-F",
        "G": "E-H",
        "H": "E-H",
        "I": "I-K",
        "J": "I-K",
        "K": "I-K",
        "L": "L-N",
        "M": "L-N",
        "N": "L-N",
        "O": "O-Q",
        "P": "O-Q",
        "Q": "O-Q",
        "R": "R-T",
        "S": "R-T",
        "T": "R-T",
        "U": "U-W",
        "V": "U-W",
        "W": "U-W",
        "X": "X-Z",
        "Y": "X-Z",
        "Z": "X-Z"
    }
    return mapping.get(first_letter, "_Others")
def safe_tool_name(tool):
    sanitized_tool = tool
    if tool[0].isdigit() or tool.lower() in yara_reserved_keywords:
        sanitized_tool = f"_{tool}"
    return sanitized_tool.replace('-','_').replace(' ','_').replace('.','_').replace('&','_and_').replace('$','')

def generate_yara_rules(output_directory):
    script_directory = os.path.dirname(os.path.realpath(__file__))
    csv_file_path = os.path.join(script_directory, 'threathunting-keywords.csv')
    output_directory = os.path.join(script_directory, output_directory)
    
    aggregated_data = defaultdict(list)
    
    with open(csv_file_path, 'r', newline='') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            tool = row['metadata_tool']
            keyword = row['keyword']
            description = row['metadata_description']
            reference = row['metadata_link']
            keyword_type = row['metadata_keyword_type']
            aggregated_data[(tool, keyword_type)].append((keyword, description, reference))
    
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
        
    for (tool, keyword_type), keywords in aggregated_data.items():
        keyword_type_dir = os.path.join(output_directory, keyword_type)
        subdirectory_name = get_subdirectory_name(tool)
        final_directory = os.path.join(keyword_type_dir, subdirectory_name)
        
        if not os.path.exists(final_directory):
            os.makedirs(final_directory)
        
        sanitized_tool = safe_tool_name(tool)
        
        with open(f"{final_directory}/{tool}.yara", 'w') as outfile:
            outfile.write(f"rule {sanitized_tool}\n")
            outfile.write("{\n")
            outfile.write("    meta:\n")
            outfile.write(f"        description = \"Detection patterns for the tool \'{tool}\' taken from the ThreatHunting-Keywords github project\" \n")
            outfile.write(f"        author = \"@mthcht\"\n")
            outfile.write(f"        reference = \"https://github.com/mthcht/ThreatHunting-Keywords\"\n")
            outfile.write(f"        tool = \"{tool}\"\n")
            outfile.write(f"        rule_category = \"{keyword_type}\"\n")
            outfile.write("\n    strings:\n")
            
            for idx, (keyword, description, reference) in enumerate(keywords):
                escaped_keyword = keyword.replace("\\", "\\\\").replace("\"", "\\\"")\
                .replace(".", "\\.").replace("*", ".*").replace(" ", "\\s")\
                .replace("|", "\\|").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")\
                .replace('+','\+').replace("&","\\&").replace('?','\?').replace('[','\[')\
                .replace(']','\]').replace("'","\\'").replace('-','\-').replace('!','\!').replace('#','\#')\
                .replace('"','\"').replace('^','\^').replace('%','\%').replace('=','\=').replace('$','\$')\
                .replace(';','\;').replace('<','\<').replace('>','\>').replace('@','\@')
                escaped_keyword = re.sub(r'^\.\*|\.\*$', '', escaped_keyword) # avoiding greedy regex for performance
                description_sanitized = description.replace("\n", " ")
                outfile.write(f"        // Description: {description_sanitized}\n")
                outfile.write(f"        // Reference: {reference}\n")
                outfile.write(f"        $string{idx+1} = /{escaped_keyword}/ nocase ascii wide\n")
                
            outfile.write("\n    condition:\n")
            outfile.write("        any of them\n")
            outfile.write("}")

if __name__ == "__main__":
    output_directory = '..\yara_rules'
    generate_yara_rules(output_directory)