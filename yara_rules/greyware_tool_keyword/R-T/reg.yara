rule reg
{
    meta:
        description = "Detection patterns for the tool 'reg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string1 = /copy\s.{0,1000}sam\.hive\s\\\\/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string2 = /copy\s.{0,1000}system\.hive\s\\\\/ nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string3 = /reg\sadd\s\"HKLM\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\"\s\/v\s.{0,1000}\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string4 = /reg\sadd\s.{0,1000}HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.{0,1000}\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string5 = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string6 = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string7 = /reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string8 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\/v\s.{0,1000}DisableAntiSpyware.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string9 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\s.{0,1000}DisableAntiVirus.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string10 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\sDisable.{0,1000}\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string11 = /reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string12 = /reg\sadd\s.{0,1000}HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.{0,1000}\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string13 = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}0.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string14 = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}4.{0,1000}\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string15 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string16 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: This particular change is associated with the handling of LAN Manager (LM) hash storage which can affect the security of password storage on the system. This command can be used as part of credential access or defense evasion techniques
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string17 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sNoLMHash\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string18 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string19 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string20 = /reg\sdelete\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/f/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string21 = /reg\squery\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\"\s\/v\sCACHEDLOGONSCOUNT/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string22 = /reg\squery\shkcu\\software\\.{0,1000}\\putty\\session/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string23 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string24 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string25 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string26 = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string27 = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string28 = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string29 = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string30 = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string31 = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string32 = /reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string33 = /reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string34 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"a\"\"m\"\"\swin32\.dll/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string35 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"ys\"\"t\"em\"\swin32\.exe/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string36 = /reg\ssave\s\"HK.{0,1000}L.{0,1000}M\\s.{0,1000}ec.{0,1000}u.{0,1000}rit.{0,1000}y.{0,1000}\"\supdate\.exe/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string37 = /reg\ssave\shklm\\sam\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string38 = /reg\ssave\sHKLM\\SAM\s.{0,1000}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string39 = /reg\ssave\shklm\\sam\ssam/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\security to a .dat file
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string40 = /reg\ssave\sHKLM\\SECURITY\s.{0,1000}c\:/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string41 = /reg\ssave\shklm\\system\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string42 = /reg\ssave\sHKLM\\SYSTEM\s.{0,1000}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string43 = /reg\ssave\shklm\\system\ssystem/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string44 = /reg\.exe\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide

    condition:
        any of them
}
