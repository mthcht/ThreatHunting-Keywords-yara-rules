import os
import re

def safe_rule_name(original_name, parent_dirs):
    """
    Generate a unique rule name by appending parent directory names.
    """
    safe_name = re.sub(r'\W+', '_', original_name)  # Replace non-alphanumeric characters
    return f"{safe_name}_{'_'.join(parent_dirs)}"

def combine_yara_rules(root_directory, output_file):
    all_rules = []  # List to store all combined rules

    for subdir, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith('.yara'):
                parent_dirs = subdir.replace(root_directory, '').split(os.sep)[:1]
                with open(os.path.join(subdir, file), 'r') as infile:
                    rule = infile.read()
                    # Extract rule name and make it unique
                    rule_name = re.search(r'rule\s+(\w+)', rule).group(1)
                    unique_rule_name = safe_rule_name(rule_name, parent_dirs)
                    # Replace original rule name with the unique one
                    rule = rule.replace(f"rule {rule_name}", f"rule {unique_rule_name}", 1)
                    all_rules.append(rule)

    # Writing all rules to all.yara
    with open(output_file, 'w') as outfile:
        for rule in all_rules:
            outfile.write(rule + "\n\n")

if __name__ == "__main__":
    root_directory = '../yara_rules/'  # Replace with your directory path
    output_file = 'all.yara'
    combine_yara_rules(root_directory, output_file)
