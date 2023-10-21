rule wmic
{
    meta:
        description = "Detection patterns for the tool 'wmic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmic"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Threat Actors ran the following command to download and execute a PowerShell payload
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1 = /\sprocess\scall\screate\s.*cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.*IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https:\/\// nocase ascii wide
        // Description: The NTDS.dit file is the heart of Active Directory including user accounts If it's found in the Temp directory it could indicate that an attacker has copied the file here in an attempt to extract sensitive information.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2 = /\\Temp\\.*\\ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in the Temp directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3 = /\\Temp\\.*\\ntds\.jfm/ nocase ascii wide
        // Description: this file shouldn't be found in the Users\Public directory. Its presence could be a sign of an ongoing or past attack.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string4 = /\\Users\\Public\\.*ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in this directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string5 = /\\Users\\Public\\.*ntds\.jfm/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /ac\si\sntds.*\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
        // Description: gather information about Windows OS version and licensing on the hosts
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string7 = /cmd\.exe\s\/C\swmic\s\/node:.*\s\/user:.*\s\/password:.*\sos\sget\scaption/ nocase ascii wide
        // Description: WMIC suspicious transfer 
        // Reference: N/A
        $string8 = /start\swmic\s\/node:\@C:\\.*\.txt\s\/user:.*\/password:.*\sprocess\scall\screate\s.*cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.*\.exe\s/ nocase ascii wide
        // Description: Lateral Movement with wmic
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string9 = /wmic\s\/.*\s\/user:administrator\sprocess\scall\screate\s.*cmd\.exe\s\/c\s/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string10 = /wmic\sprocess\scall\screate.*ntdsutil\s.*ac\si\sntds.*\sifm.*create\sfull/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string11 = /wmic\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: User Enumeration
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string12 = /wmic\suseraccount\sget\s\/ALL\s\/format:csv/ nocase ascii wide
        // Description: list AV products with wmic
        // Reference: N/A
        $string13 = /wmic.*\/Namespace:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName/ nocase ascii wide
        // Description: Execute a .EXE file stored as an Alternate Data Stream (ADS)
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string14 = /wmic\.exe\sprocess\scall\screate\s.*\.txt:.*\.exe/ nocase ascii wide

    condition:
        any of them
}