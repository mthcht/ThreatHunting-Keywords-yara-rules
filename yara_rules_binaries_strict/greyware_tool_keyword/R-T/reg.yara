rule reg
{
    meta:
        description = "Detection patterns for the tool 'reg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string1 = " /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string2 = " /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string3 = " /v \"DisableIOAVProtection\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string4 = " /v \"DisableOnAccessProtection\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string5 = " /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string6 = " /v \"DisableScanOnRealtimeEnable\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string7 = " /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f" nocase ascii wide
        // Description: reg command used to disabled real time monitoring defender - often abused by attackers
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string8 = " /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: 
        // Reference: N/A
        $string9 = /\\reg\.exe.{0,100}\ssave\sHKLM/ nocase ascii wide
        // Description: a copy of the registry hive
        // Reference: N/A
        $string10 = /\\Windows\\Temp\\sam\.save/ nocase ascii wide
        // Description: Once AccessVBOM is enabled - an attacker can use VBA to embed or execute malicious code
        // Reference: https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/
        $string11 = /\\Word\\Security\s\/v\sAccessVBOM\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: exporting registry keys
        // Reference: https://blog.talosintelligence.com/uat-5647-romcom/
        $string12 = "cmd /C reg export hkcu" nocase ascii wide
        // Description: exporting registry keys
        // Reference: https://blog.talosintelligence.com/uat-5647-romcom/
        $string13 = "cmd /C reg export hklm" nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string14 = /copy\s.{0,100}sam\.hive\s\\\\/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string15 = /copy\s.{0,100}system\.hive\s\\\\/ nocase ascii wide
        // Description: disables User Account Control
        // Reference: https://github.com/nathanlopez/Stitch/blob/8e22e91c94237959c02d521aab58dc7e3d994cea/PyLib/disableUAC.py#L8
        $string16 = /HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.{0,100}\s\/v\sEnableLUA\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string17 = /HKLM\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels\\"\s\/v\sDisableDevTunnelsInVisualStudio\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string18 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\\"C\:\\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string19 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\\"D\:\\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string20 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\\"E\:\\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string21 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\\"F\:\\\\"/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string22 = "Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d \"1\" /f" nocase ascii wide
        // Description: modifies the Windows Registry to enable Remote Desktop connections by setting the fDenyTSConnections value to 0
        // Reference: N/A
        $string23 = /reg\sadd\s\\"HKEY\sLOCAL\sMACHINE\\SYSTEM\\CurentControlSet\\Control\\Terminal\sServer\\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: could be used to manipulate system behavior or remove evidence
        // Reference: https://github.com/xiaoy-sec/Pentest_Note/blob/52156f816f0c2497c25343c2e872130193acca80/wiki/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/Windows%E6%8F%90%E6%9D%83/RDP%26Firewall/%E5%88%A0%E9%99%A4%E7%97%95%E8%BF%B9.md?plain=1#L4
        $string24 = /reg\sadd\s\\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Servers\\"/ nocase ascii wide
        // Description: Hides the user from the login screen - a tactic often used for stealthy persistence.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string25 = /reg\sadd\s\\"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\\"\s\/v\s.{0,100}\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string26 = /reg\sadd\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\"\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string27 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\\"\s\/f\s\/v\sfAllowUnsolicited\s\/t\sREG_DWORD\s\/d\s\\"00000001\\"/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string28 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\\"\s\/f\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s\\"00000000\\"/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string29 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\\"\s\/f\s\/v\sUserAuthentication\s\/t\sREG_DWORD\s\/d\s\\"00000000\\"/ nocase ascii wide
        // Description: Sophos disable tamper protection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string30 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Sophos\\SAVService\\TamperProtection\\"\s\/t\sREG_DWORD\s\/v\sEnabled\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Open passwords mimic + open rdp 3389 - used by many ransomware groups
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string31 = /reg\sadd\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Enables Remote Desktop Protocol (RDP) connections by setting fDenyTSConnections to 0
        // Reference: N/A
        $string32 = /reg\sadd\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string33 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\WinStations\\RDP\-Tcp\\"\s\/f\s\/v\sSecurityLayer\s\/t\sREG_DWORD\s\/d\s\\"00000001\\"/ nocase ascii wide
        // Description: Sophos disable tamper protection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string34 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\SAVService\\"\s\/t\sREG_DWORD\s\/v\sStart\s\/d\s0x00000004\s\/f/ nocase ascii wide
        // Description: Sophos disable tamper protection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string35 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Sophos\sEndpoint\sDefense\\TamperProtection\\Config\\"\s\/t\sREG_DWORD\s\/v\sSAVEnabled\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Sophos disable tamper protection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string36 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Sophos\sEndpoint\sDefense\\TamperProtection\\Config\\"\s\/t\sREG_DWORD\s\/v\sSEDEnabled\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Sophos disable tamper protection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string37 = /REG\sADD\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Sophos\sMCS\sAgent\\"\s\/t\sREG_DWORD\s\/v\sStart\s\/d\s0x00000004\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string38 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sDefender\sSecurity\sCenter\\Notifications\\"\s\/v\sDisableNotifications\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string39 = /reg\sadd\s\\"HKLM\\Software\\Microsoft\\Windows\sDefender\\"\s\/v\sDisableAntiSpyware\sand\sDisableAntiVirus\s\/t\sREG_DWORD\s\/d\s\\"1\\"\s\/f/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string40 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\HelpPane\.exe\\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\\"\%windir\%\\system32\\cmd\.exe\\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string41 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\Magnify\.exe\\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\\"\%windir\%\\system32\\cmd\.exe\\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string42 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\\"\%windir\%\\system32\\cmd\.exe\\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string43 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe\\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\\"\%windir\%\\system32\\cmd\.exe\\"/ nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string44 = /reg\sadd\s\\"HKLM\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\\"\s\/v\s.{0,100}\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: disables the UAC consent prompt for administrators
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string45 = /REG\sADD\s\\"hklm\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\s\\"ConsentPromptBehaviorAdmin\\"\s\/t\sREG_Dword\s\/d\s00000000\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string46 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\sConsentPromptBehaviorAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disables the consent prompt for administrators
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string47 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\sConsentPromptBehaviorAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string48 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\sEnableLUA\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string49 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\sPromptOnSecureDesktop\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disables the secure desktop for User Account Control (UAC) prompts
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string50 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"\s\/v\sPromptOnSecureDesktop\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hides the nvspbind component from the uninstall programs list - making it harder for users or administrators to detect or remove the program
        // Reference: N/A
        $string51 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\nvspbind\\"\s\/v\sSystemComponent\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string52 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\"\s\/v\sAllowFastServiceStartup\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string53 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\"\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string54 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\"\s\/v\sServiceKeepAlive\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string55 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\\"\s\/v\sDisableBehaviorMonitoring\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string56 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\\"\s\/v\sDisableIOAVProtection\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string57 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\\"\s\/v\sDisableOnAccessProtection\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string58 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\\"\s\/v\sDisableRealtimeMonitoring\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string59 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\\"\s\/v\sDisableScanOnRealtimeEnable\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string60 = /reg\sadd\s\\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\Reporting\\"\s\/v\s\\"DisableEnhancedNotifications\\"\s\/t\sREG_DWORD\s\/d\s\\"1\\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string61 = /reg\sadd\s\\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\\"\s\/v\s\\"SpyNetReporting\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string62 = /reg\sadd\s\\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\\"\s\/v\s\\"SubmitSamplesConsent\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string63 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\\"\s\/v\sDisableBlockAtFirstSeen\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string64 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\\"\s\/v\sLocalSettingOverrideSpyNetReporting\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string65 = /REG\sADD\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\\"\s\/v\sSubmitSamplesConsent\s\/t\sREG_DWORD\s\/d\s2\s\/f/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string66 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\"\s\/f\s\/v\sPackagePointAndPrintOnly\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string67 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\"\s\/f\s\/v\sPackagePointAndPrintServerList\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string68 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\ListofServers\\"\s\/f\s\/v\s1\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string69 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PointAndPrint\\"\s\/f\s\/v\sRestrictDriverInstallationToAdministrators\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: Uninstall TrendMicro
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string70 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Wow6432Node\\TrendMicro\\PC\-cillinNTCorp\\CurrentVersion\\Misc\.\\"\s\/v\s\\"Allow\sUninstall\\"\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string71 = /REG\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sEveryoneIncludesAnonymous\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string72 = /REG\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sRestrictAnonymous\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: enable Remote Desktop connections with reg.exe
        // Reference: N/A
        $string73 = /reg\sadd\s\\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Enables Remote Desktop Protocol (RDP) connections by setting fDenyTSConnections to 0
        // Reference: N/A
        $string74 = /reg\sadd\s\\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Tunnel RDP through port 443
        // Reference: N/A
        $string75 = /REG\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\TerminalServer\\WinStations\\RDP\-Tcp\\"\s\/v\sPortNumber\s\/t\sREG_DWORD\s\/d\s443\s\/f/ nocase ascii wide
        // Description: disable logging related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string76 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: disable logging related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string77 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string78 = /REG\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionPipes\s\/t\sREG_MULTI_SZ\s\/d\ssrvsvc\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string79 = /REG\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionShares\s\/t\sREG_MULTI_SZ\s\/d\sshare\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string80 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string81 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string82 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string83 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string84 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string85 = /reg\sadd\s\\"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\"\s\/v\s\\"Start\\"\s\/t\sREG_DWORD\s\/d\s\\"4\\"\s\/f/ nocase ascii wide
        // Description: disables Windows Defender by setting its start value to 4 (disabled)
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string86 = /REG\sADD\s\\"HKLM\\SYSTEM\\CurrentControlSet\\services\\WinDefend\\"\s\/v\sStart\s\/t\sREG_DWORD\s\/d\s4\s\/f/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string87 = /reg\sadd\s.{0,100}HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.{0,100}\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string88 = /REG\sADD\s.{0,100}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.{0,100}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,100}\\windows\\system32\\cmd\.exe.{0,100}\s\/f/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string89 = /REG\sADD\s.{0,100}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.{0,100}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,100}\\windows\\system32\\cmd\.exe.{0,100}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string90 = /reg\sadd\s.{0,100}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\".{0,100}\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string91 = /reg\sadd\s.{0,100}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\".{0,100}\/v\s.{0,100}DisableAntiSpyware.{0,100}\s\/t\sREG_DWORD\s\/d\s.{0,100}1.{0,100}\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string92 = /reg\sadd\s.{0,100}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,100}\s\/v\s.{0,100}DisableAntiVirus.{0,100}\s\/t\sREG_DWORD\s\/d\s.{0,100}1.{0,100}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string93 = /reg\sadd\s.{0,100}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,100}\s\/v\sDisable.{0,100}\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string94 = /reg\sadd\s.{0,100}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string95 = /reg\sadd\s.{0,100}HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.{0,100}\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string96 = /reg\sadd\s.{0,100}HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.{0,100}\s\/v\s.{0,100}Start.{0,100}\s\/t\sREG_DWORD\s\/d\s.{0,100}0.{0,100}\s\/f/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string97 = /reg\sadd\s.{0,100}HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.{0,100}\s\/v\s.{0,100}Start.{0,100}\s\/t\sREG_DWORD\s\/d\s.{0,100}4.{0,100}\s\/f/ nocase ascii wide
        // Description: command used in the Dispossessor ransomware group notes - The account will no longer be visible on the Windows login screen.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string98 = /reg\sadd\s\\\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\\\\"\s\/t\sREG_DWORD\s\/f\s\/d\s0\s\/v\s/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string99 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string100 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: This particular change is associated with the handling of LAN Manager (LM) hash storage which can affect the security of password storage on the system. This command can be used as part of credential access or defense evasion techniques
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string101 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sNoLMHash\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f/ nocase ascii wide
        // Description: Disables Protected Process Light (PPL) for Local Security Authority (LSA). This reduces system security by making LSA more vulnerable to tampering - exposing credentials
        // Reference: N/A
        $string102 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string103 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string104 = /reg\sadd\sHKLM\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels\s\/v\sDisableDevTunnelsInVisualStudio\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: Disables Protected Process Light (PPL) for Local Security Authority (LSA). This reduces system security by making LSA more vulnerable to tampering - exposing credentials
        // Reference: N/A
        $string105 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string106 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s\/f\s1/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string107 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Enables WDigest authentication - storing plaintext credentials in memory. This exposes the system to credential theft attacks
        // Reference: N/A
        $string108 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Open passwords mimic + open rdp 3389 - used by many ransomware groups
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string109 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string110 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/f\s\/d\s1/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string111 = /reg\sdelete\s\\"HKCR\\.{0,100}\\shellex\\ContextMenuHandlers\\EPP\\"\s\/f/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string112 = /reg\sdelete\s\\"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\\"\s\/f/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string113 = /reg\sdelete\s\\"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string114 = /Reg\sDelete\s\\"HKCU\\software\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SUPERAntiSpyware\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string115 = /reg\sdelete\s\\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Windows\sDefender\\"\s\/f/ nocase ascii wide
        // Description: delete terminal server client entries from the registry - erasing potential evidence of RDP connections
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Ransom/Win32/Ergop/Ransom_Win32_Ergop_A_.yar#L10
        $string116 = /reg\sdelete\s\\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Default\\"\s\/va\s\/f/ nocase ascii wide
        // Description: delete terminal server client entries from the registry - erasing potential evidence of RDP connections
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Ransom/Win32/Ergop/Ransom_Win32_Ergop_A_.yar#L10
        $string117 = /reg\sdelete\s\\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Servers\\"\s\/f/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string118 = /reg\sdelete\s\\"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\\"\s\/v\s\\"Windows\sDefender\\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string119 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"AvastUI\.exe\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string120 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"AvastUI\.exe\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string121 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"AVGUI\.exe\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string122 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"AVGUI\.exe\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string123 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Avira\sSystrayStartTrigger\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string124 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Avira\sSystrayStartTrigger\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string125 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"ClamWin\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string126 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"ClamWin\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string127 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"COMODO\sInternet\sSecurity\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string128 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"COMODO\sInternet\sSecurity\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string129 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"egui\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string130 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"egui\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string131 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"IseUI\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string132 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"IseUI\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string133 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"QHSafeTray\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string134 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"QHSafeTray\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string135 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SBAMTray\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string136 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SBAMTray\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string137 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SBRegRebootCleaner\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string138 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SBRegRebootCleaner\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string139 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SUPERAntiSpyware\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string140 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SUPERAntiSpyware\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string141 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SUPERAntiSpyware\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string142 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"SUPERAntiSpyware\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string143 = /reg\sdelete\s\\"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Windows\sDefender\\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string144 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Zillya\sAntivirus\\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string145 = /Reg\sDelete\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Zillya\sAntivirus\\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string146 = /reg\sdelete\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels\\"\s\/v\sDisableDevTunnelsInVisualStudio\s\/f/ nocase ascii wide
        // Description: Remove Sophos Registry Keys
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string147 = /REG\sDelete\s\\"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\"\s\/v\s\\"Sophos\sAutoUpdate\sMonitor\\"\s\/f/ nocase ascii wide
        // Description: Delete stuffs related to windows defender registry
        // Reference: N/A
        $string148 = /reg\sdelete\s.{0,100}\\Software\\Microsoft\\Windows\sDefender/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string149 = /reg\sdelete\s.{0,100}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,100}\s\/f/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string150 = /reg\sdelete\sHKLM\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels/ nocase ascii wide
        // Description: Deletes the registry key responsible for enabling Windows Defender under System Settings.
        // Reference: N/A
        $string151 = /reg\sdelete.{0,100}\\Software\\Microsoft\\SystemSettings\\SettingId\\SystemSettings_WindowsDefender_UseWindowsDefender/ nocase ascii wide
        // Description: Deletes the Windows Event Log channel for Windows Defender WHC (Windows Health Center
        // Reference: N/A
        $string152 = /reg\sdelete.{0,100}\\Software\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft\-Windows\-Windows\sDefender\/WHC/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string153 = /reg\squery\s\\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\\"\s\/v\sCACHEDLOGONSCOUNT/ nocase ascii wide
        // Description: Query registry for Terminal Server Client settings
        // Reference: N/A
        $string154 = /reg\squery\s.{0,100}\\Software\\Microsoft\\Terminal\sServer\sClient\\Default\\"/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string155 = "reg query HKCU /f passw /t REG_SZ /s" nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string156 = "reg query HKCU /f pwd /t REG_SZ /s" nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string157 = /reg\squery\shkcu\\software\\.{0,100}\\putty\\session/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string158 = /reg\squery\shkcu\\software\\.{0,100}\\putty\\session/ nocase ascii wide
        // Description: queries the Windows Registry for entries in the Run key (indicate programs set to execute upon user login - potentially revealing persistence mechanisms)
        // Reference: N/A
        $string159 = /reg\squery\sHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string160 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string161 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string162 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string163 = "reg query HKLM /f passw /t REG_SZ /s" nocase ascii wide
        // Description: Searching the Registry for Passwords
        // Reference: N/A
        $string164 = "reg query HKLM /f password  /t REG_SZ  /s " nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string165 = "reg query HKLM /f pwd /t REG_SZ /s" nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string166 = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string167 = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string168 = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string169 = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string170 = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string171 = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string172 = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string173 = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string174 = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string175 = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string176 = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: credential access with reg
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string177 = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string178 = /reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string179 = /reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string180 = /reg\ssave\s\\"HK\\"L\\"\\"M\\s\\"\\"a\\"\\"m\\"\\"\swin32\.dll/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string181 = /reg\ssave\s\\"HK\\"L\\"\\"M\\s\\"\\"ys\\"\\"t\\"em\\"\swin32\.exe/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string182 = /reg\ssave\s\\"HK.{0,100}L.{0,100}M\\s.{0,100}ec.{0,100}u.{0,100}rit.{0,100}y.{0,100}\\"\supdate\.exe/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string183 = /reg\ssave\shklm\\sam\s.{0,100}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string184 = /reg\ssave\sHKLM\\SAM\s.{0,100}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string185 = /reg\ssave\shklm\\sam\ssam/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\security to a .dat file
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string186 = /reg\ssave\sHKLM\\SECURITY\s/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string187 = /reg\ssave\shklm\\system\s.{0,100}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string188 = /reg\ssave\sHKLM\\SYSTEM\s.{0,100}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string189 = /reg\ssave\shklm\\system\ssystem/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string190 = /reg\.exe\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sEveryoneIncludesAnonymous\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string191 = /reg\.exe\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sRestrictAnonymous\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string192 = /reg\.exe\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionPipes\s\/t\sREG_MULTI_SZ\s\/d\ssrvsvc\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string193 = /reg\.exe\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionShares\s\/t\sREG_MULTI_SZ\s\/d\sshare\s\/f/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string194 = /reg\.exe\sadd\s.{0,100}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string195 = /reg\.exe\sdelete\s\\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Default\\"\s\/va\s\/f/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string196 = /reg\.exe\sdelete\s\\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Servers\\"\s\/f/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string197 = /reg\.exe\ssave\shklm\\sam\s/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string198 = /reg\.exe\ssave\shklm\\security\s/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string199 = /reg\.exe\ssave\shklm\\system\s/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string200 = /reg\.exe\\"\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sEveryoneIncludesAnonymous\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string201 = /reg\.exe\\"\sADD\s\\"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\"\s\/v\sRestrictAnonymous\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string202 = /reg\.exe\\"\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionPipes\s\/t\sREG_MULTI_SZ\s\/d\ssrvsvc\s\/f/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string203 = /reg\.exe\\"\sADD\s\\"HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"\s\/v\sNullSessionShares\s\/t\sREG_MULTI_SZ\s\/d\sshare\s\/f/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string204 = /reg\.exe\\"\ssave\shklm\\sam\s/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string205 = /reg\.exe\\"\ssave\shklm\\security\s/ nocase ascii wide
        // Description: saves a copy of the registry hive
        // Reference: N/A
        $string206 = /reg\.exe\\"\ssave\shklm\\system\s/ nocase ascii wide
        // Description: Delete stuffs related to windows defender registry
        // Reference: N/A
        $string207 = /reg\.exe.{0,100}\sdelete\s.{0,100}\\Software\\Microsoft\\Windows\sDefender/ nocase ascii wide
        // Description: Deletes the Windows Event Log channel for Windows Defender WHC (Windows Health Center
        // Reference: N/A
        $string208 = /reg\.exe.{0,100}\sdelete\s.{0,100}\\Software\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft\-Windows\-Windows\sDefender\/WHC/ nocase ascii wide
        // Description: Deletes the registry key responsible for enabling Windows Defender under System Settings.
        // Reference: N/A
        $string209 = /reg\.exe.{0,100}\sdelete.{0,100}\\Software\\Microsoft\\SystemSettings\\SettingId\\SystemSettings_WindowsDefender_UseWindowsDefender/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
