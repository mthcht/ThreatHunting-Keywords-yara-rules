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
        $string1 = /.{0,1000}\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.{0,1000}IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https:\/\/.{0,1000}/ nocase ascii wide
        // Description: The NTDS.dit file is the heart of Active Directory including user accounts If it's found in the Temp directory it could indicate that an attacker has copied the file here in an attempt to extract sensitive information.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2 = /.{0,1000}\\Temp\\.{0,1000}\\ntds\.dit.{0,1000}/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in the Temp directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3 = /.{0,1000}\\Temp\\.{0,1000}\\ntds\.jfm.{0,1000}/ nocase ascii wide
        // Description: this file shouldn't be found in the Users\Public directory. Its presence could be a sign of an ongoing or past attack.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string4 = /.{0,1000}\\Users\\Public\\.{0,1000}ntds\.dit.{0,1000}/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in this directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string5 = /.{0,1000}\\Users\\Public\\.{0,1000}ntds\.jfm.{0,1000}/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /.{0,1000}ac\si\sntds.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}/ nocase ascii wide
        // Description: gather information about Windows OS version and licensing on the hosts
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string7 = /.{0,1000}cmd\.exe\s\/C\swmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sos\sget\scaption.{0,1000}/ nocase ascii wide
        // Description: Enable WinRM remotely with wmic
        // Reference: N/A
        $string8 = /.{0,1000}process\scall\screate\s\"powershell\senable\-psremoting\s\-force\".{0,1000}/ nocase ascii wide
        // Description: WMIC suspicious transfer 
        // Reference: N/A
        $string9 = /.{0,1000}start\swmic\s\/node:\@C:\\.{0,1000}\.txt\s\/user:.{0,1000}\/password:.{0,1000}\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement with wmic
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string10 = /.{0,1000}wmic\s\/.{0,1000}\s\/user:administrator\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\s.{0,1000}/ nocase ascii wide
        // Description: Execute file hosted over SMB on remote system with specified credential
        // Reference: N/A
        $string11 = /.{0,1000}wmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sprocess\scall\screate\s\"\\\\.{0,1000}\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Remotely start RDP with wmic
        // Reference: N/A
        $string12 = /.{0,1000}wmic\s\/node:.{0,1000}\spath\sWin32_TerminalServiceSetting\swhere\sAllowTSConnections\=\"0\"\scall\sSetAllowTSConnections\s\"1\".{0,1000}/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string13 = /.{0,1000}wmic\s\/node:.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}computersystem\sget\susername.{0,1000}/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string14 = /.{0,1000}wmic\s\/node:.{0,1000}localhost.{0,1000}computersystem\sget\susername.{0,1000}/ nocase ascii wide
        // Description: get domain name with wmic
        // Reference: N/A
        $string15 = /.{0,1000}wmic\scomputersystem\sget\sdomain.{0,1000}/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string16 = /.{0,1000}wmic\sprocess\scall\screate.{0,1000}ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\sifm.{0,1000}create\sfull.{0,1000}/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string17 = /.{0,1000}wmic\sservice\sbrief.{0,1000}/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string18 = /.{0,1000}wmic\sSHADOWCOPY\s\/nointeractive.{0,1000}/ nocase ascii wide
        // Description: User Enumeration
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string19 = /.{0,1000}wmic\suseraccount\sget\s\/ALL\s\/format:csv.{0,1000}/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string20 = /.{0,1000}wmic\svolume\slist\sbrief.{0,1000}/ nocase ascii wide
        // Description: list AV products with wmic
        // Reference: N/A
        $string21 = /.{0,1000}wmic.{0,1000}\/Namespace:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName.{0,1000}/ nocase ascii wide
        // Description: Execute a .EXE file stored as an Alternate Data Stream (ADS)
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string22 = /.{0,1000}wmic\.exe\sprocess\scall\screate\s.{0,1000}\.txt:.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: call cmd.exe with wmic
        // Reference: N/A
        $string23 = /.{0,1000}wmic\.exe\sprocess\scall\screate\s.{0,1000}cmd\s\/c\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
