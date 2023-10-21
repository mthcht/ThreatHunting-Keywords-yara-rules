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
        $string1 = /copy\s.*sam\.hive\s\\\\/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string2 = /copy\s.*system\.hive\s\\\\/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string3 = /reg\sadd\s.*HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.*\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string4 = /REG\sADD\s.*HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.*\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.*\\windows\\system32\\cmd\.exe.*\s\/f/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string5 = /REG\sADD\s.*HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.*\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.*\\windows\\system32\\cmd\.exe.*\s\/f/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string6 = /reg\sadd\s.*HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\".*\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string7 = /reg\sadd\s.*HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\".*\/v\s.*DisableAntiSpyware.*\s\/t\sREG_DWORD\s\/d\s.*1.*\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string8 = /reg\sadd\s.*HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.*\s\/v\s.*DisableAntiVirus.*\s\/t\sREG_DWORD\s\/d\s.*1.*\s\/f/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string9 = /reg\sadd\s.*HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.*\s\/v\sDisable.*\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string10 = /reg\sadd\s.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.*\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string11 = /reg\sadd\s.*HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.*\s\/v\s.*Start.*\s\/t\sREG_DWORD\s\/d\s.*0.*\s\/f/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string12 = /reg\sadd\s.*HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.*\s\/v\s.*Start.*\s\/t\sREG_DWORD\s\/d\s.*4.*\s\/f/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string13 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string14 = /reg\sdelete\s.*HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.*\s\/f/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string15 = /reg\squery\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\"\s\/v\sCACHEDLOGONSCOUNT/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string16 = /reg\squery\shkcu\\software\\.*\\putty\\session/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string17 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string18 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string19 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string20 = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string21 = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string22 = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string23 = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string24 = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string25 = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string26 = /reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string27 = /reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string28 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"a\"\"m\"\"\swin32\.dll/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string29 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"ys\"\"t\"em\"\swin32\.exe/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string30 = /reg\ssave\s\"HK.*L.*M\\s.*ec.*u.*rit.*y.*\"\supdate\.exe/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string31 = /reg\ssave\shklm\\sam\s.*\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string32 = /reg\ssave\sHKLM\\SAM\sc:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string33 = /reg\ssave\shklm\\sam\ssam/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string34 = /reg\ssave\shklm\\system\s.*\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string35 = /reg\ssave\sHKLM\\SYSTEM\sc:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string36 = /reg\ssave\shklm\\system\ssystem/ nocase ascii wide

    condition:
        any of them
}