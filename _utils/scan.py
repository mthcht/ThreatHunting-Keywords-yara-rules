from pathlib import Path
import yara
import argparse
import json
import re
import os
import sys
from datetime import datetime

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

def scan_large_file_in_chunks(file_path, rules, patterns, out_f=None, chunk_size=MAX_FILE_SIZE):
    results = []
    with open(file_path, 'rb') as f:
        offset = 0
        while chunk := f.read(chunk_size):
            matches = rules.match(data=chunk)
            if matches:
                for match in matches:
                    for string_match in match.strings:
                        for instance in string_match.instances:
                            result_dict = {
                                'rule_name': match.rule,
                                'file_path': str(file_path),
                                'offset': offset + instance.offset,
                                'string_id': string_match.identifier,
                                'string_pattern': patterns.get(string_match.identifier, 'unknown'),
                                'matched_string_UTF8': instance.matched_data.decode('utf-8', 'ignore')
                            }
                            results.append(result_dict)
                            key = (patterns.get(string_match.identifier, 'unknown'), match.rule, str(file_path))
                            summary_count[key] = summary_count.get(key, 0) + 1
                if results:
                    formatted_results = json.dumps(results, indent=4)
                    print(formatted_results)
                    if out_f:
                        out_f.write(formatted_results + '\n')
            offset += chunk_size

def scan_files_with_yara(yara_rule_files, target, output_file=None, extension=None, bypass_limit=False):
    for yara_rule_file in yara_rule_files:
        print(f"Scanning {target} with rule file {yara_rule_file}")
        try:
            rules = yara.compile(filepath=yara_rule_file)
        except yara.SyntaxError as e:
            print(f"YARA Syntax Error in {yara_rule_file}: {e}")
            continue
        patterns = read_yara_patterns(yara_rule_file)
        target_path = Path(target)

        if output_file:
            try:
                out_f = open(output_file, 'a', encoding='utf-8')
            except IOError as e:
                print(f"Failed to open output file {output_file}: {e}")
                out_f = None
        else:
            out_f = None

        try:
            if target_path.is_file():
                if not extension or target_path.suffix == extension:
                    if bypass_limit and target_path.stat().st_size > MAX_FILE_SIZE:
                        scan_large_file_in_chunks(target_path, rules, patterns, out_f)
                    else:
                        scan_and_output(yara_rule_file, target_path, rules, patterns, out_f)
            elif target_path.is_dir():
                for file_path in target_path.rglob('*' + (extension if extension else '')):
                    if bypass_limit and file_path.stat().st_size > MAX_FILE_SIZE:
                        scan_large_file_in_chunks(file_path, rules, patterns, out_f)
                    else:
                        scan_and_output(yara_rule_file, file_path, rules, patterns, out_f)
            else:
                print(f"{target} is neither a valid file nor a directory.")
        except PermissionError:
            print(f"Permission denied for {target}. Skipping.")

        if out_f:
            out_f.close()

def get_yara_files(yara_paths):
    yara_files = []
    for yara_path in yara_paths:
        if os.path.isdir(yara_path):
            for root, dirs, files in os.walk(yara_path):
                for file in files:
                    if file.endswith('.yara') or file.endswith('.yar'):
                        yara_files.append(os.path.join(root, file))
        elif os.path.isfile(yara_path):
            yara_files.append(yara_path)
    return yara_files

def scan_and_output(yara_rule_file, file_path, rules, patterns, out_f=None):
    results = []
    try:
        if file_path.is_file() and file_path.stat().st_size <= MAX_FILE_SIZE:
            with open(file_path, 'rb') as f:
                matches = rules.match(data=f.read())
                if matches:
                    for match in matches:
                        for string_match in match.strings:
                            for instance in string_match.instances:
                                result_dict = {
                                    'rule_name': Path(yara_rule_file).name,
                                    'file_path': str(file_path),
                                    'offset': instance.offset,
                                    'string_id': string_match.identifier,
                                    'string_pattern': patterns.get(string_match.identifier, 'unknown'),
                                    'matched_string_UTF8': instance.matched_data.decode('utf-8', 'ignore')
                                }
                                results.append(result_dict)
                                key = (patterns.get(string_match.identifier, 'unknown'), Path(yara_rule_file).name, str(file_path))
                                summary_count[key] = summary_count.get(key, 0) + 1

                    if results:
                        formatted_results = json.dumps(results, indent=4)
                        print(formatted_results)
                        if out_f:
                            out_f.write(formatted_results + '\n')
                    else:
                        print("... nothing found")
        else:
            print(f"Skipping {file_path}. File size exceeds 64MB or is not a regular file.")
    except PermissionError:
        print(f"Permission denied for {file_path}. Skipping.")
    except Exception as e:
        print(f"An error occurred while scanning {file_path}: {e}")

def generate_output_filename(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_path = Path(target)
    if target_path.is_dir():
        output_name = f"{target_path.name}_{timestamp}.txt"
        output_path = target_path / output_name
    elif target_path.is_file():
        output_name = f"{target_path.stem}_{timestamp}.txt"
        output_path = target_path.parent / output_name
    else:
        output_path = Path.cwd() / f"scan_results_{timestamp}.txt"
    return str(output_path)

def validate_target_path(target):
    target_path = Path(target)
    if not target_path.exists():
        print(f"Error: The target path '{target}' does not exist.")
        sys.exit(1)
    if not (target_path.is_file() or target_path.is_dir()):
        print(f"Error: The target path '{target}' is neither a file nor a directory.")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a file or directory with one or multiple YARA rules")
    parser.add_argument("-y", "--yara", required=True, nargs='+', help="Path(s) to YARA rule file(s) or directory(ies) containing them")
    parser.add_argument("-t", "--target", required=True, nargs='+', help="Path(s) to target file(s) or directory(ies) to scan")
    parser.add_argument("-o", "--output", help="Path to the output file to save scan results (json format)")
    parser.add_argument("-e", "--extension", help="File extension to filter files for scanning, e.g., '.exe'")
    parser.add_argument("--bypass_limit", action='store_true', help="Enable scanning for files larger than 64MB by splitting them into chunks")

    args = parser.parse_args()

    yara_files = get_yara_files(args.yara)
    if not yara_files:
        print("No valid YARA files found.")
        sys.exit(1)

    # Process each target path in the list
    for target in args.target:
        validate_target_path(target)
        output_file = args.output if args.output else generate_output_filename(target)
        scan_files_with_yara(yara_files, target, output_file, args.extension, args.bypass_limit)

    print("\n--- Summary of Detections ---")
    for (string_pattern, rule_name, file_path), count in summary_count.items():
        print(f"Count: {count}, Rule File: {rule_name}, Target File: {file_path}, String Pattern: {string_pattern}")

