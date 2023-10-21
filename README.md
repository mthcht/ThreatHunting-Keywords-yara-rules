# ThreatHunting-Keywords-yaml-rules
yaml detection rules for hunting with the [threathunting-keywords](https://github.com/mthcht/ThreatHunting-Keywords) project

All the detection patterns from the [threathunting-keywords](https://github.com/mthcht/ThreatHunting-Keywords) project are automatically organized in yara rules for each tool and keyword type.
- 🛠️ **offensive tool keyword**: These keywords relate to offensive tools or exhibit high confidence of malicious intent. It's crucial that these terms are relevant and reliable in detecting potential threats (low false positive rate).
- 🛠️ **greyware tool keyword**: Keywords in this category correspond to 'legitimate' tools that are abused by malicious actors. As these tools also have legitimate uses, the potential for false positives is inherently higher. It's important to interpret these results with the understanding that not all detections may signify malicious activity
- 🛠️ **signature keyword**: These keywords may not directly associate with tools but may include security product signature names, specific strings, or words significant in threat detection.

Organized in alphabetical order to bypass the GitHub limitation of 1000 files per directory.

![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/aa92027f-354a-4706-a019-a9d318eb0ffd)

## Scanning with the yara rules

### Scanning a directory or a file with a yara rule:
![2023-10-20 20_23_59-(1) mthcht on X_ _The #ThreatHunting Keywords project is slowly progressing, alm](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/fda16d4c-e56d-49a2-8095-c9b920ebae0a)

![2023-10-20 20_29_27-(1) mthcht on X_ _The #ThreatHunting Keywords project is slowly progressing, alm](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/0acea256-369b-4e2a-8e82-f51b69a1c1ee)

### Scanning multiple directories or files with multiple yara rules:
![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/64cf98a8-dd5c-45de-946d-a9243d570b92)

![image](https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/assets/75267080/37dc6e05-52c7-4778-bd22-62b960569fd0)


