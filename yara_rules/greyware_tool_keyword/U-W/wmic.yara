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
        $string1 = /\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.{0,1000}IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https:\/\// nocase ascii wide
        // Description: The NTDS.dit file is the heart of Active Directory including user accounts If it's found in the Temp directory it could indicate that an attacker has copied the file here in an attempt to extract sensitive information.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2 = /\\Temp\\.{0,1000}\\ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in the Temp directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3 = /\\Temp\\.{0,1000}\\ntds\.jfm/ nocase ascii wide
        // Description: this file shouldn't be found in the Users\Public directory. Its presence could be a sign of an ongoing or past attack.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string4 = /\\Users\\Public\\.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in this directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string5 = /\\Users\\Public\\.{0,1000}ntds\.jfm/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /ac\si\sntds.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
        // Description: gather information about Windows OS version and licensing on the hosts
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string7 = /cmd\.exe\s\/C\swmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sos\sget\scaption/ nocase ascii wide
        // Description: Enable WinRM remotely with wmic
        // Reference: N/A
        $string8 = /process\scall\screate\s\"powershell\senable\-psremoting\s\-force\"/ nocase ascii wide
        // Description: WMIC suspicious transfer 
        // Reference: N/A
        $string9 = /start\swmic\s\/node:\@C:\\.{0,1000}\.txt\s\/user:.{0,1000}\/password:.{0,1000}\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: Lateral Movement with wmic
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string10 = /wmic\s\/.{0,1000}\s\/user:administrator\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\s/ nocase ascii wide
        // Description: Execute file hosted over SMB on remote system with specified credential
        // Reference: N/A
        $string11 = /wmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sprocess\scall\screate\s\"\\\\.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Remotely start RDP with wmic
        // Reference: N/A
        $string12 = /wmic\s\/node:.{0,1000}\spath\sWin32_TerminalServiceSetting\swhere\sAllowTSConnections\=\"0\"\scall\sSetAllowTSConnections\s\"1\"/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string13 = /wmic\s\/node:.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string14 = /wmic\s\/node:.{0,1000}localhost.{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get domain name with wmic
        // Reference: N/A
        $string15 = /wmic\scomputersystem\sget\sdomain/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string16 = /wmic\sprocess\scall\screate.{0,1000}ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\sifm.{0,1000}create\sfull/ nocase ascii wide
        // Description: list all running processes and their command lines on a Windows system
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string17 = /wmic\sprocess\sget\scommandline\s\-all/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string18 = /wmic\sservice\sbrief/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string19 = /wmic\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string20 = /wmic\sshadowcopy\sdelete/ nocase ascii wide
        // Description: User Enumeration
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string21 = /wmic\suseraccount\sget\s\/ALL\s\/format:csv/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string22 = /wmic\svolume\slist\sbrief/ nocase ascii wide
        // Description: list AV products with wmic
        // Reference: N/A
        $string23 = /wmic.{0,1000}\/Namespace:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName/ nocase ascii wide
        // Description: Execute a .EXE file stored as an Alternate Data Stream (ADS)
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string24 = /wmic\.exe\sprocess\scall\screate\s.{0,1000}\.txt:.{0,1000}\.exe/ nocase ascii wide
        // Description: call cmd.exe with wmic
        // Reference: N/A
        $string25 = /wmic\.exe\sprocess\scall\screate\s.{0,1000}cmd\s\/c\s/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string26 = /wmic\.exe\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string27 = /wmic\.exe\sshadowcopy\sdelete/ nocase ascii wide

    condition:
        any of them
}
