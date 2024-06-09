# ThreatHunting-Keywords-yara-rules

![B9lGW1697885670](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/98dfefe9-f915-4dc7-bb72-d8a9118cf0d8)

Yara rules for Threat Hunting sessions

All the detection patterns from the [threathunting-keywords](https://github.com/mthcht/ThreatHunting-Keywords) project are automatically organized in yara rules for each tool and keyword type.
- 🛠️ **offensive tool keyword**: These keywords relate to offensive tools or exhibit high confidence of malicious intent. It's crucial that these terms are relevant and reliable in detecting potential threats (low false positive rate).
- 🛠️ **greyware tool keyword**: Keywords in this category correspond to 'legitimate' tools that are abused by malicious actors. As these tools also have legitimate uses, the potential for false positives is inherently higher. It's important to interpret these results with the understanding that not all detections may signify malicious activity
- 🛠️ **signature keyword**: These keywords may not directly associate with tools but may include security product signature names, specific strings, or words significant in threat detection.

Organized in alphabetical order to bypass the GitHub limitation of 1000 files per directory.

![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/fda53ec2-28cb-4f16-bbb9-36f5afba922c)


# Scanning with the yara rules
The python script [scan.py](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/blob/main/_utils/scan.py) enables cross-platform scanning of files and directories using the extracted YARA rules
 - `-y` or `--yara`: Path to the YARA rule file(s) or directory containing them
- `-t` or `--target`:Path to the target file or directory to scan
- `-o` or `--output`: Path to the output file to save scan results in json format

## Scanning a directory or a file with a yara rule:
![2023-10-20 20_23_59-(1) mthcht on X_ _The #ThreatHunting Keywords project is slowly progressing, alm](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/fda16d4c-e56d-49a2-8095-c9b920ebae0a)

Example of the json output file using `-o` or `--output`: 
![2023-10-20 20_29_27-(1) mthcht on X_ _The #ThreatHunting Keywords project is slowly progressing, alm](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/0acea256-369b-4e2a-8e82-f51b69a1c1ee)

## Scanning multiple directories or files with multiple yara rules:
![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/64cf98a8-dd5c-45de-946d-a9243d570b92)

![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/37dc6e05-52c7-4778-bd22-62b960569fd0)


