import os
import re

def safe_rule_name(original_name, parent_dirs):
    """
    Generate a unique rule name by appending parent directory names.
    """
    safe_name = re.sub(r'\W+', '_', original_name)  # Replace non-alphanumeric characters
    safe_name = re.sub(r'^rule_', '', safe_name)    # Remove existing 'rule_' prefix to avoid redundancy
    return f"rule_{safe_name}_{'_'.join(parent_dirs)}"

def unique_string_id(original_id, rule_suffix):
    """
    Generate a unique string identifier.
    """
    return f"{original_id}_{rule_suffix}"

def preserve_and_restore_conditions(rule_content, rule_suffix):
    """
    Preserve '2 of ($string*)', 'any of ($string*)', and '$metadata_regex_*' in the condition section.
    """
    preserved_conditions = []

    # Patterns to preserve
    condition_patterns = [
        r'(2\s+of\s*\(\$string\*\))',
        r'(any\s+of\s*\(\$string\*\))',
        r'(for\s+any\s+of\s*\(\$metadata_regex_\*\))'
    ]

    for pattern in condition_patterns:
        for match in re.finditer(pattern, rule_content):
            start, end = match.span()
            preserved_conditions.append((start, end, match.group(0)))

    # Temporarily replace preserved conditions with placeholders
    for i, (_, _, text) in enumerate(preserved_conditions):
        rule_content = rule_content.replace(text, f"__PLACEHOLDER_CONDITION_{i}__")

    return rule_content, preserved_conditions

def restore_preserved_conditions(rule_content, preserved_conditions):
    """
    Restore preserved patterns in the condition section.
    """
    for i, (_, _, text) in enumerate(preserved_conditions):
        rule_content = rule_content.replace(f"__PLACEHOLDER_CONDITION_{i}__", text)
    return rule_content

def modify_rule_strings(rule_content, rule_suffix):
    """
    Modify all string identifiers in the rule content to be unique.
    """
    string_ids = re.findall(r'\$(string\d+)', rule_content)  # Only match string identifiers like $string1
    for string_id in set(string_ids):  # Ensure each string ID is processed only once
        unique_id = unique_string_id(string_id, rule_suffix)
        rule_content = re.sub(rf'\${string_id}\b', f'${unique_id}', rule_content)
    return rule_content

def combine_yara_rules(root_directory, output_file, sub_directory=None):
    """
    Combine YARA rules from a single root directory.
    """
    all_rules = []  # List to store all combined rules

    for subdir, dirs, files in os.walk(root_directory):
        if sub_directory and sub_directory not in subdir:
            continue  # Skip directories not matching the target

        for file in files:
            if file not in ("all.yara", "offensive_tools.yara", "greyware_tools.yara"):
                if file.endswith('.yara'):
                    parent_dirs = subdir.replace(root_directory, '').split(os.sep)[:1]
                    parent_dirs = [d for d in parent_dirs if d]  # Filter empty elements
                    with open(os.path.join(subdir, file), 'r') as infile:
                        rule = infile.read()
                        rule_name_search = re.search(r'rule\s+(\w+)', rule)
                        if rule_name_search:
                            rule_name = rule_name_search.group(1)
                            unique_rule_name = safe_rule_name(rule_name, parent_dirs)
                            rule_suffix = unique_rule_name.replace('rule_', '')  # Suffix for string IDs

                            # Preserve and replace conditions
                            rule, preserved_conditions = preserve_and_restore_conditions(rule, rule_suffix)

                            # Modify rule name
                            rule = rule.replace(f"rule {rule_name}", f"rule {unique_rule_name}", 1)

                            # Modify strings
                            rule = modify_rule_strings(rule, rule_suffix)

                            # Restore preserved conditions
                            rule = restore_preserved_conditions(rule, preserved_conditions)

                            all_rules.append(rule)

    # Writing all rules to the output file
    with open(output_file, 'w') as outfile:
        for rule in all_rules:
            outfile.write(rule + "\n\n")

if __name__ == "__main__":
    # Define the root directories
    directories = [
        '../yara_rules/',
        '../yara_rules_binaries_strict/'
    ]

    for root_directory in directories:
        # Combine all rules for the current root directory
        output_file_all = os.path.join(root_directory, 'all.yara')
        combine_yara_rules(root_directory, output_file_all)

        # Offensive tools for the current root directory
        output_file_offensive = os.path.join(root_directory, 'offensive_tools.yara')
        combine_yara_rules(root_directory, output_file_offensive, 'offensive_tool_keyword')

        # Greyware tools for the current root directory
        output_file_greyware = os.path.join(root_directory, 'greyware_tools.yara')
        combine_yara_rules(root_directory, output_file_greyware, 'greyware_tool_keyword')
