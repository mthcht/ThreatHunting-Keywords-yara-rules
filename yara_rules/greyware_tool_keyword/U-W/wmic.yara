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
        $string1 = /\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.{0,1000}IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https\:\/\// nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string2 = /\.exe\sshadowcopy\sdelete/ nocase ascii wide
        // Description: Windows Defender Tampering Via Wmic
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string3 = /\/NAMESPACE\:\\\\root\\Microsoft\\Windows\\Defender\sPATH\sMSFT_MpPreference\scall\sAdd\sExclusionExtension\=exe\sForce\=True/ nocase ascii wide
        // Description: The NTDS.dit file is the heart of Active Directory including user accounts If it's found in the Temp directory it could indicate that an attacker has copied the file here in an attempt to extract sensitive information.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string4 = /\\Temp\\.{0,1000}\\ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in the Temp directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string5 = /\\Temp\\.{0,1000}\\ntds\.jfm/ nocase ascii wide
        // Description: this file shouldn't be found in the Users\Public directory. Its presence could be a sign of an ongoing or past attack.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /\\Users\\Public\\.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in this directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string7 = /\\Users\\Public\\.{0,1000}ntds\.jfm/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string8 = /ac\si\sntds.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
        // Description: suspicious lateral movement command executing payload from suspicious directories
        // Reference: N/A
        $string9 = /cmd\s\s\/c\swmic\s\/node\:.{0,1000}\sprocess\scall\screate\s\"C\:\\programdata\\/ nocase ascii wide
        // Description: suspicious lateral movement command executing payload from suspicious directories
        // Reference: N/A
        $string10 = /cmd\s\s\/c\swmic\s\/node\:.{0,1000}\sprocess\scall\screate\s\"C\:\\Temp\\/ nocase ascii wide
        // Description: suspicious lateral movement command executing payload from suspicious directories
        // Reference: N/A
        $string11 = /cmd\s\s\/c\swmic\s\/node\:.{0,1000}\sprocess\scall\screate\s\"C\:\\users\\.{0,1000}\\AppData\\Local\\Temp/ nocase ascii wide
        // Description: suspicious lateral movement command executing payload from suspicious directories
        // Reference: N/A
        $string12 = /cmd\s\s\/c\swmic\s\/node\:.{0,1000}\sprocess\scall\screate\s\"C\:\\users\\Public/ nocase ascii wide
        // Description: gather information about Windows OS version and licensing on the hosts
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string13 = /cmd\.exe\s\/C\swmic\s\/node\:.{0,1000}\s\/user\:.{0,1000}\s\/password\:.{0,1000}\sos\sget\scaption/ nocase ascii wide
        // Description: Enable WinRM remotely with wmic
        // Reference: N/A
        $string14 = /process\scall\screate\s\"powershell\senable\-psremoting\s\-force\"/ nocase ascii wide
        // Description: WMIC suspicious transfer 
        // Reference: N/A
        $string15 = /start\swmic\s\/node\:\@C\:\\.{0,1000}\.txt\s\/user\:.{0,1000}\/password\:.{0,1000}\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string16 = /Win32_Shadowcopy\s\|\sForEach\-Object\s\{\$_\.Delete\(\)\;/ nocase ascii wide
        // Description: Lateral Movement with wmic
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string17 = /wmic\s\/.{0,1000}\s\/user\:administrator\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\s/ nocase ascii wide
        // Description: Execute file hosted over SMB on remote system with specified credential
        // Reference: N/A
        $string18 = /wmic\s\/node\:.{0,1000}\s\/user\:.{0,1000}\s\/password\:.{0,1000}\sprocess\scall\screate\s\"\\\\.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Remotely start RDP with wmic
        // Reference: N/A
        $string19 = /wmic\s\/node\:.{0,1000}\spath\sWin32_TerminalServiceSetting\swhere\sAllowTSConnections\=\"0\"\scall\sSetAllowTSConnections\s\"1\"/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string20 = /wmic\s\/node\:.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string21 = /wmic\s\/node\:.{0,1000}localhost.{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get domain name with wmic
        // Reference: N/A
        $string22 = /wmic\scomputersystem\sget\sdomain/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string23 = /wmic\sprocess\scall\screate.{0,1000}ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\sifm.{0,1000}create\sfull/ nocase ascii wide
        // Description: list all running processes and their command lines on a Windows system
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string24 = /wmic\sprocess\sget\scommandline\s\-all/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string25 = /wmic\sservice\sbrief/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string26 = /wmic\sservice\swhere\s\"name\slike\s\'\%veeam\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string27 = /wmic\sservice\swhere\s\"name\slike\s\'acronisagent\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string28 = /wmic\sservice\swhere\s\"name\slike\s\'acrsch2svc\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string29 = /wmic\sservice\swhere\s\"name\slike\s\'agntsvc\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string30 = /wmic\sservice\swhere\s\"name\slike\s\'arsm\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string31 = /wmic\sservice\swhere\s\"name\slike\s\'backp\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string32 = /wmic\sservice\swhere\s\"name\slike\s\'backup\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string33 = /wmic\sservice\swhere\s\"name\slike\s\'cbservi\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string34 = /wmic\sservice\swhere\s\"name\slike\s\'cbvscserv\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string35 = /wmic\sservice\swhere\s\"name\slike\s\'shadowprotectsvc\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string36 = /wmic\sservice\swhere\s\"name\slike\s\'spxservice\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string37 = /wmic\sservice\swhere\s\"name\slike\s\'sqbcoreservice\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string38 = /wmic\sservice\swhere\s\"name\slike\s\'stc_endpt_svc\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string39 = /wmic\sservice\swhere\s\"name\slike\s\'storagecraft\simagemanager\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string40 = /wmic\sservice\swhere\s\"name\slike\s\'veeam\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string41 = /wmic\sservice\swhere\s\"name\slike\s\'vsnapvss\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string42 = /wmic\sservice\swhere\s\"name\slike\s\'vssvc\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: stopping backup service
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string43 = /wmic\sservice\swhere\s\"name\slike\s\'wbengine\%\'\"\scall\sstopservice/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string44 = /wmic\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string45 = /wmic\sshadowcopy\sdelete/ nocase ascii wide
        // Description: User Enumeration
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string46 = /wmic\suseraccount\sget\s\/ALL\s\/format\:csv/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string47 = /wmic\svolume\slist\sbrief/ nocase ascii wide
        // Description: list AV products with wmic
        // Reference: N/A
        $string48 = /wmic.{0,1000}\/Namespace\:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName/ nocase ascii wide
        // Description: Execute a .EXE file stored as an Alternate Data Stream (ADS)
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string49 = /wmic\.exe\sprocess\scall\screate\s.{0,1000}\.txt\:.{0,1000}\.exe/ nocase ascii wide
        // Description: call cmd.exe with wmic
        // Reference: N/A
        $string50 = /wmic\.exe\sprocess\scall\screate\s.{0,1000}cmd\s\/c\s/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string51 = /wmic\.exe\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string52 = /wmic\.exe\sshadowcopy\sdelete/ nocase ascii wide

    condition:
        any of them
}
