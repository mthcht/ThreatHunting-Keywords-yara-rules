from pathlib import Path
import yara
import argparse
import json
import re
import os

banner='''
:::   :::     :::     :::::::::      :::            ::::::::   ::::::::      :::     ::::    ::: ::::    ::: :::::::::: :::::::::  
:+:   :+:   :+: :+:   :+:    :+:   :+: :+:         :+:    :+: :+:    :+:   :+: :+:   :+:+:   :+: :+:+:   :+: :+:        :+:    :+: 
 +:+ +:+   +:+   +:+  +:+    +:+  +:+   +:+        +:+        +:+         +:+   +:+  :+:+:+  +:+ :+:+:+  +:+ +:+        +:+    +:+ 
  +#++:   +#++:++#++: +#++:++#:  +#++:++#++:       +#++:++#++ +#+        +#++:++#++: +#+ +:+ +#+ +#+ +:+ +#+ +#++:++#   +#++:++#:  
   +#+    +#+     +#+ +#+    +#+ +#+     +#+              +#+ +#+        +#+     +#+ +#+  +#+#+# +#+  +#+#+# +#+        +#+    +#+ 
   #+#    #+#     #+# #+#    #+# #+#     #+#       #+#    #+# #+#    #+# #+#     #+# #+#   #+#+# #+#   #+#+# #+#        #+#    #+# 
   ###    ###     ### ###    ### ###     ###        ########   ########  ###     ### ###    #### ###    #### ########## ###    ###
by @mthcht  
'''
print(banner)
summary_count = {}


MAX_FILE_SIZE = 64 * 1024 * 1024  # 64MB limit file size

def read_yara_patterns(yara_file_path):
    patterns = {}
    with open(yara_file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            match = re.search(r'(\$[\w\d_]+)\s*=\s*(.*)', line.strip())
            if match:
                current_string_id, pattern = match.groups()
                patterns[current_string_id] = pattern
    return patterns

def scan_files_with_yara(yara_rule_files, target, output_file=None):
    for yara_rule_file in yara_rule_files:
        print(f"Scanning {target} with rule file {yara_rule_file}")
        rules = yara.compile(filepath=yara_rule_file)
        patterns = read_yara_patterns(yara_rule_file)
        target_path = Path(target)

        if output_file:
            out_f = open(output_file, 'a')

        try:
            if target_path.is_file():
                scan_and_output(yara_rule_file,target_path, rules, patterns, out_f if output_file else None)
            elif target_path.is_dir():
                for file_path in target_path.rglob('*'):
                    scan_and_output(yara_rule_file,file_path, rules, patterns, out_f if output_file else None)
            else:
                print(f"{target} is neither a valid file nor a directory.")
        except PermissionError:
            print(f"Permission denied for {target}. Skipping.")

        if output_file:
            out_f.close()

def get_yara_files(yara_path):
    yara_files = []
    if os.path.isdir(yara_path):
        for root, dirs, files in os.walk(yara_path):
            for file in files:
                if file.endswith('.yara'):
                    yara_files.append(os.path.join(root, file))
    elif os.path.isfile(yara_path):
        yara_files.append(yara_path)
    return yara_files
        
def scan_and_output(yara_rule_file, file_path, rules, patterns, out_f=None):
    results = []
    try:
        if file_path.stat().st_size <= MAX_FILE_SIZE:
        if file_path.is_file() and file_path.stat().st_size <= MAX_FILE_SIZE:
            with open(file_path, 'rb') as f:
                print(f"Scanning {file_path} with {yara_rule_file} ...")
                matches = rules.match(data=f.read())
                if matches:
                    for match in matches:  # Loop through each match object
                        for string_match in match.strings:  # Loop through each string match inside the match object
                            string_pattern = patterns.get(string_match[1], 'unknown (error)')
                            rule_name = str(yara_rule_file)
                            result_dict = {
                                'rule_name': rule_name,
                                'file_path': str(file_path),
                                'offset': string_match[0],
                                'string_id': string_match[1],
                                'string_pattern': string_pattern,
                                'matched_string': string_match[2].decode('utf-8', 'ignore')
                            }
                            results.append(result_dict)

                            key = (string_pattern, rule_name, str(file_path))
                            summary_count[key] = summary_count.get(key, 0) + 1

                    formatted_results = json.dumps(results, indent=4)
                    print(formatted_results)
                    if out_f:
                        out_f.write(formatted_results)
                else:
                    print("... nothing found")
        else:
            print(f"Skipping {file_path}. File size exceeds 64MB.")
    except PermissionError:
        print(f"Permission denied for {file_path}. Skipping.")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a file or directory with one or multiple YARA rules")
    parser.add_argument("-y", "--yara", required=True, help="Path to the YARA rule file(s) or directory containing them")
    parser.add_argument("-t", "--target", required=True, help="Path to the target file or directory to scan")
    parser.add_argument("-o", "--output", help="Path to the output file to save scan results (json format)")

    args = parser.parse_args()
    
    yara_files = get_yara_files(args.yara)
    
    if not yara_files:
        print("No valid YARA files found.")
        exit(1)
    
    scan_files_with_yara(yara_files, args.target, args.output)
    #print(banner)
    print("\n--- Summary of Detections ---")
    for (string_pattern,rule_name,file_path), count in summary_count.items():
        print(f"Count: {count}, Rule File: {rule_name}, Target File: {file_path}, string_pattern: {string_pattern}")
