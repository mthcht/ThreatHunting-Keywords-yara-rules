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
        $string1 = /.{0,1000}copy\s.{0,1000}sam\.hive\s\\\\.{0,1000}/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string2 = /.{0,1000}copy\s.{0,1000}system\.hive\s\\\\.{0,1000}/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string3 = /.{0,1000}reg\sadd\s.{0,1000}HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.{0,1000}\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f.{0,1000}/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string4 = /.{0,1000}REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string5 = /.{0,1000}REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string6 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f.{0,1000}/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string7 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\/v\s.{0,1000}DisableAntiSpyware.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string8 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\s.{0,1000}DisableAntiVirus.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string9 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\sDisable.{0,1000}\s\/t\sREG_DWORD\s\/d\s1\s\/f.{0,1000}/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string10 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.{0,1000}\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0.{0,1000}/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string11 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}0.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string12 = /.{0,1000}reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}4.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string13 = /.{0,1000}reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s.{0,1000}/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string14 = /.{0,1000}reg\sdelete\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/f.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string15 = /.{0,1000}reg\squery\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\"\s\/v\sCACHEDLOGONSCOUNT.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string16 = /.{0,1000}reg\squery\shkcu\\software\\.{0,1000}\\putty\\session.{0,1000}/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string17 = /.{0,1000}reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string18 = /.{0,1000}reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string19 = /.{0,1000}reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string20 = /.{0,1000}reg\squery\shklm\\software\\OpenSSH.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string21 = /.{0,1000}reg\squery\shklm\\software\\OpenSSH\\Agent.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string22 = /.{0,1000}reg\squery\shklm\\software\\realvnc.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string23 = /.{0,1000}reg\squery\shklm\\software\\realvnc\\Allusers.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string24 = /.{0,1000}reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver.{0,1000}/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string25 = /.{0,1000}reg\squery\shklm\\software\\realvnc\\vncserver.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string26 = /.{0,1000}reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string27 = /.{0,1000}reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string28 = /.{0,1000}reg\ssave\s\"HK\"L\"\"M\\s\"\"a\"\"m\"\"\swin32\.dll.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string29 = /.{0,1000}reg\ssave\s\"HK\"L\"\"M\\s\"\"ys\"\"t\"em\"\swin32\.exe.{0,1000}/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string30 = /.{0,1000}reg\ssave\s\"HK.{0,1000}L.{0,1000}M\\s.{0,1000}ec.{0,1000}u.{0,1000}rit.{0,1000}y.{0,1000}\"\supdate\.exe.{0,1000}/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string31 = /.{0,1000}reg\ssave\shklm\\sam\s.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string32 = /.{0,1000}reg\ssave\sHKLM\\SAM\sc:.{0,1000}/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string33 = /.{0,1000}reg\ssave\shklm\\sam\ssam.{0,1000}/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string34 = /.{0,1000}reg\ssave\shklm\\system\s.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string35 = /.{0,1000}reg\ssave\sHKLM\\SYSTEM\sc:.{0,1000}/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string36 = /.{0,1000}reg\ssave\shklm\\system\ssystem.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
