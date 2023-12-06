import os
import re

def safe_rule_name(original_name, parent_dirs):
    """
    Generate a unique rule name by appending parent directory names.
    """
    safe_name = re.sub(r'\W+', '_', original_name)  # Replace non-alphanumeric characters
    return f"{safe_name}_{'_'.join(parent_dirs)}"

def unique_string_id(original_id, rule_suffix):
    """
    Generate a unique string identifier.
    """
    return f"{original_id}_{rule_suffix}"

def modify_rule_strings(rule_content, rule_suffix):
    """
    Modify all string identifiers in the rule content to be unique.
    """
    modified_content = rule_content
    string_ids = re.findall(r'\$(\w+)', rule_content)
    for string_id in set(string_ids):  # Ensure each string ID is processed only once
        unique_id = unique_string_id(string_id, rule_suffix)
        modified_content = re.sub(rf'\${string_id}\b', f'${unique_id}', modified_content)
    return modified_content

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
                    rule_suffix = unique_rule_name.replace('rule_', '')  # Suffix for string IDs
                    # Replace original rule name with the unique one
                    rule = rule.replace(f"rule {rule_name}", f"rule {unique_rule_name}", 1)
                    # Modify string identifiers within the rule
                    rule = modify_rule_strings(rule, rule_suffix)
                    all_rules.append(rule)

    # Writing all rules to all.yara
    with open(output_file, 'w') as outfile:
        for rule in all_rules:
            outfile.write(rule + "\n\n")

if __name__ == "__main__":
    root_directory = '../yara_rules/'  # Replace with your directory path
    output_file = os.path.join(root_directory, 'all.yara')
    combine_yara_rules(root_directory, output_file)
