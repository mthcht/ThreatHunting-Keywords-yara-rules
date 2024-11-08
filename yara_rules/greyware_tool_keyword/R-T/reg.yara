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
        $string1 = /\s\/v\s\"DisableAntiSpyware\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string2 = /\s\/v\s\"DisableAntiVirus\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string3 = /\s\/v\s\"DisableIOAVProtection\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string4 = /\s\/v\s\"DisableOnAccessProtection\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string5 = /\s\/v\s\"DisableRealtimeMonitoring\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string6 = /\s\/v\s\"DisableScanOnRealtimeEnable\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string7 = /\s\/v\s\"MpEnablePus\"\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: exporting registry keys
        // Reference: https://blog.talosintelligence.com/uat-5647-romcom/
        $string8 = /cmd\s\/C\sreg\sexport\shkcu/ nocase ascii wide
        // Description: exporting registry keys
        // Reference: https://blog.talosintelligence.com/uat-5647-romcom/
        $string9 = /cmd\s\/C\sreg\sexport\shklm/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string10 = /copy\s.{0,1000}sam\.hive\s\\\\/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string11 = /copy\s.{0,1000}system\.hive\s\\\\/ nocase ascii wide
        // Description: disables User Account Control
        // Reference: https://github.com/nathanlopez/Stitch/blob/8e22e91c94237959c02d521aab58dc7e3d994cea/PyLib/disableUAC.py#L8
        $string12 = /HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.{0,1000}\s\/v\sEnableLUA\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string13 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\"C\:\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string14 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\"D\:\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string15 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\"E\:\\\"/ nocase ascii wide
        // Description: add entire disks exclusions to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string16 = /powershell\.exe\s\-nop\s\-c\sAdd\-MpPreference\s\-ExclusionPath\s\"F\:\\\"/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string17 = /Real\-Time\sProtection\"\s\/v\s\"DisableBehaviorMonitoring\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: modifies the Windows Registry to enable Remote Desktop connections by setting the fDenyTSConnections value to 0
        // Reference: N/A
        $string18 = /reg\sadd\s\"HKEY\sLOCAL\sMACHINE\\SYSTEM\\CurentControlSet\\Control\\Terminal\sServer\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: could be used to manipulate system behavior or remove evidence
        // Reference: https://github.com/xiaoy-sec/Pentest_Note/blob/52156f816f0c2497c25343c2e872130193acca80/wiki/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/Windows%E6%8F%90%E6%9D%83/RDP%26Firewall/%E5%88%A0%E9%99%A4%E7%97%95%E8%BF%B9.md?plain=1#L4
        $string19 = /reg\sadd\s\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Servers\"/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string20 = /reg\sadd\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\"\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string21 = /REG\sADD\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\"\s\/f\s\/v\sfAllowUnsolicited\s\/t\sREG_DWORD\s\/d\s\"00000001\"/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string22 = /REG\sADD\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\"\s\/f\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s\"00000000\"/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string23 = /REG\sADD\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Terminal\sServices\"\s\/f\s\/v\sUserAuthentication\s\/t\sREG_DWORD\s\/d\s\"00000000\"/ nocase ascii wide
        // Description: making Remote Desktop Protocol (RDP) more vulnerable to unauthorized access.
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L19
        $string24 = /REG\sADD\s\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\\WinStations\\RDP\-Tcp\"\s\/f\s\/v\sSecurityLayer\s\/t\sREG_DWORD\s\/d\s\"00000001\"/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string25 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sDefender\sSecurity\sCenter\\Notifications\"\s\/v\sDisableNotifications\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string26 = /reg\sadd\s\"HKLM\\Software\\Microsoft\\Windows\sDefender\"\s\/v\sDisableAntiSpyware\sand\sDisableAntiVirus\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string27 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\HelpPane\.exe\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\"\%windir\%\\system32\\cmd\.exe\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string28 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\Magnify\.exe\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\"\%windir\%\\system32\\cmd\.exe\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string29 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\"\%windir\%\\system32\\cmd\.exe\"/ nocase ascii wide
        // Description: modify the Image File Execution Options to substitute accessibility tools with cmd.exe enabling privilege escalation by launching an elevated command prompt
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/cmd.cmd#L12
        $string30 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe\"\s\/f\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\"\%windir\%\\system32\\cmd\.exe\"/ nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string31 = /reg\sadd\s\"HKLM\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\"\s\/v\s.{0,1000}\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: disables the UAC consent prompt for administrators
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string32 = /REG\sADD\s\"hklm\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\s\"ConsentPromptBehaviorAdmin\"\s\/t\sREG_Dword\s\/d\s00000000\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string33 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\sConsentPromptBehaviorAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disables the consent prompt for administrators
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string34 = /reg\sadd\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\sConsentPromptBehaviorAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string35 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\sEnableLUA\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable security notifications / adjust User Account Control (UAC) settings / reduce security prompts for administrative actions
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string36 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\sPromptOnSecureDesktop\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disables the secure desktop for User Account Control (UAC) prompts
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string37 = /reg\sadd\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"\s\/v\sPromptOnSecureDesktop\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string38 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\"\s\/v\sAllowFastServiceStartup\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string39 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\"\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable Windows Defender - prevent it from starting quickly and prevent services from staying alive
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string40 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\"\s\/v\sServiceKeepAlive\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string41 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\"\s\/v\sDisableBehaviorMonitoring\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string42 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\"\s\/v\sDisableIOAVProtection\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string43 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\"\s\/v\sDisableOnAccessProtection\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string44 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\"\s\/v\sDisableRealtimeMonitoring\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable real-time protection features of Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string45 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Real\-Time\sProtection\"\s\/v\sDisableScanOnRealtimeEnable\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string46 = /reg\sadd\s\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\Reporting\"\s\/v\s\"DisableEnhancedNotifications\"\s\/t\sREG_DWORD\s\/d\s\"1\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string47 = /reg\sadd\s\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\"\s\/v\s\"SpyNetReporting\"\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: disable protection features of Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string48 = /reg\sadd\s\"HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\"\s\/v\s\"SubmitSamplesConsent\"\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string49 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\"\s\/v\sDisableBlockAtFirstSeen\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string50 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\"\s\/v\sLocalSettingOverrideSpyNetReporting\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: reduce Windows Defender's ability to block suspicious files and prevent sample submissions to Microsoft
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string51 = /REG\sADD\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\SpyNet\"\s\/v\sSubmitSamplesConsent\s\/t\sREG_DWORD\s\/d\s2\s\/f/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string52 = /reg\sadd\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\"\s\/f\s\/v\sPackagePointAndPrintOnly\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string53 = /reg\sadd\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\"\s\/f\s\/v\sPackagePointAndPrintServerList\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string54 = /reg\sadd\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\ListofServers\"\s\/f\s\/v\s1\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string55 = /reg\sadd\s\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PointAndPrint\"\s\/f\s\/v\sRestrictDriverInstallationToAdministrators\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: enable Remote Desktop connections with reg.exe
        // Reference: N/A
        $string56 = /reg\sadd\s\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer\"\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Tunnel RDP through port 443
        // Reference: N/A
        $string57 = /REG\sADD\s\"HKLM\\System\\CurrentControlSet\\Control\\TerminalServer\\WinStations\\RDP\-Tcp\"\s\/v\sPortNumber\s\/t\sREG_DWORD\s\/d\s443\s\/f/ nocase ascii wide
        // Description: disable logging related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string58 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: disable logging related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string59 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string60 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string61 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string62 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string63 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string64 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disable Windows Defender-related services
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string65 = /reg\sadd\s\"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\"\s\/v\s\"Start\"\s\/t\sREG_DWORD\s\/d\s\"4\"\s\/f/ nocase ascii wide
        // Description: disables Windows Defender by setting its start value to 4 (disabled)
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string66 = /REG\sADD\s\"HKLM\\SYSTEM\\CurrentControlSet\\services\\WinDefend\"\s\/v\sStart\s\/t\sREG_DWORD\s\/d\s4\s\/f/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string67 = /reg\sadd\s.{0,1000}HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.{0,1000}\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string68 = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string69 = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string70 = /reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string71 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\/v\s.{0,1000}DisableAntiSpyware.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string72 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\s.{0,1000}DisableAntiVirus.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string73 = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\sDisable.{0,1000}\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string74 = /reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string75 = /reg\sadd\s.{0,1000}HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.{0,1000}\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string76 = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}0.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string77 = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}4.{0,1000}\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string78 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for Lateral Movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string79 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: This particular change is associated with the handling of LAN Manager (LM) hash storage which can affect the security of password storage on the system. This command can be used as part of credential access or defense evasion techniques
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string80 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sNoLMHash\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string81 = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string82 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s\/f\s1/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string83 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: allows the storage of plaintext passwords in memory
        // Reference: N/A
        $string84 = /reg\sadd\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential\s\/t\sREG_DWORD\s\/f\s\/d\s1/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string85 = /reg\sdelete\s\"HKCR\\.{0,1000}\\shellex\\ContextMenuHandlers\\EPP\"\s\/f/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string86 = /reg\sdelete\s\"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\"\s\/f/ nocase ascii wide
        // Description: remove the Windows Defender context menu options
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string87 = /reg\sdelete\s\"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string88 = /Reg\sDelete\s\"HKCU\\software\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SUPERAntiSpyware\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string89 = /reg\sdelete\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Windows\sDefender\"\s\/f/ nocase ascii wide
        // Description: delete terminal server client entries from the registry - erasing potential evidence of RDP connections
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Ransom/Win32/Ergop/Ransom_Win32_Ergop_A_.yar#L10
        $string90 = /reg\sdelete\s\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Default\"\s\/va\s\/f/ nocase ascii wide
        // Description: delete terminal server client entries from the registry - erasing potential evidence of RDP connections
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Ransom/Win32/Ergop/Ransom_Win32_Ergop_A_.yar#L10
        $string91 = /reg\sdelete\s\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal\sServer\sClient\\Servers\"\s\/f/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string92 = /reg\sdelete\s\"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\"\s\/v\s\"Windows\sDefender\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string93 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"AvastUI\.exe\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string94 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"AvastUI\.exe\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string95 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"AVGUI\.exe\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string96 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"AVGUI\.exe\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string97 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Avira\sSystrayStartTrigger\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string98 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Avira\sSystrayStartTrigger\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string99 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"ClamWin\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string100 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"ClamWin\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string101 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"COMODO\sInternet\sSecurity\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string102 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"COMODO\sInternet\sSecurity\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string103 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"egui\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string104 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"egui\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string105 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"IseUI\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string106 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"IseUI\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string107 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"QHSafeTray\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string108 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"QHSafeTray\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string109 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SBAMTray\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string110 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SBAMTray\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string111 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SBRegRebootCleaner\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string112 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SBRegRebootCleaner\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string113 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SUPERAntiSpyware\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string114 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SUPERAntiSpyware\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string115 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SUPERAntiSpyware\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string116 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"SUPERAntiSpyware\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: remove Windows Defender from the system tray
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string117 = /reg\sdelete\s\"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Windows\sDefender\"\s\/f/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string118 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Zillya\sAntivirus\"\s\/f\s\/reg\:32/ nocase ascii wide
        // Description: prevents security tools from launching automatically
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string119 = /Reg\sDelete\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\s\/v\s\"Zillya\sAntivirus\"\s\/f\s\/reg\:64/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string120 = /reg\sdelete\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/f/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string121 = /reg\squery\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\"\s\/v\sCACHEDLOGONSCOUNT/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string122 = /reg\squery\sHKCU\s\/f\spassw\s\/t\sREG_SZ\s\/s/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string123 = /reg\squery\sHKCU\s\/f\spwd\s\/t\sREG_SZ\s\/s/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string124 = /reg\squery\shkcu\\software\\.{0,1000}\\putty\\session/ nocase ascii wide
        // Description: queries the Windows Registry for entries in the Run key (indicate programs set to execute upon user login - potentially revealing persistence mechanisms)
        // Reference: N/A
        $string125 = /reg\squery\sHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string126 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string127 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string128 = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string129 = /reg\squery\sHKLM\s\/f\spassw\s\/t\sREG_SZ\s\/s/ nocase ascii wide
        // Description: Searching the Registry for Passwords
        // Reference: N/A
        $string130 = /reg\squery\sHKLM\s\/f\spassword\s\s\/t\sREG_SZ\s\s\/s\s/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string131 = /reg\squery\sHKLM\s\/f\spwd\s\/t\sREG_SZ\s\/s/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string132 = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string133 = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string134 = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string135 = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string136 = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string137 = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string138 = /reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string139 = /reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string140 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"a\"\"m\"\"\swin32\.dll/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string141 = /reg\ssave\s\"HK\"L\"\"M\\s\"\"ys\"\"t\"em\"\swin32\.exe/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string142 = /reg\ssave\s\"HK.{0,1000}L.{0,1000}M\\s.{0,1000}ec.{0,1000}u.{0,1000}rit.{0,1000}y.{0,1000}\"\supdate\.exe/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string143 = /reg\ssave\shklm\\sam\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string144 = /reg\ssave\sHKLM\\SAM\s.{0,1000}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string145 = /reg\ssave\shklm\\sam\ssam/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\security to a .dat file
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string146 = /reg\ssave\sHKLM\\SECURITY\s/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string147 = /reg\ssave\shklm\\system\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string148 = /reg\ssave\sHKLM\\SYSTEM\s.{0,1000}c\:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string149 = /reg\ssave\shklm\\system\ssystem/ nocase ascii wide
        // Description: Windows Defender Tampering Via registry
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string150 = /reg\.exe\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\Threats\\ThreatIDDefaultAction/ nocase ascii wide

    condition:
        any of them
}
