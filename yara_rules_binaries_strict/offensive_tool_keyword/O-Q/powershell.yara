rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: powershell obfuscations techniques observed by malwares - reversed net user
        // Reference: N/A
        $string1 = " imaohw" nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed net user
        // Reference: N/A
        $string2 = " resu ten" nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed http://
        // Reference: N/A
        $string3 = "//:ptth" nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed https://
        // Reference: N/A
        $string4 = "//:sptth" nocase ascii wide
        // Description: impair the defenses of the targeted system by disabling ETW logging for PowerShell. This can make it difficult for security teams to monitor and analyze PowerShell activities on the system potentially allowing adversaries to perform malicious actions without being detected
        // Reference: N/A
        $string5 = /\[Reflection\.Assembly\]\:\:LoadWithPartialName\(\'System\.Core\'\)\.GetType\(\'System\.Diagnostics\.Eventing\.EventProvider\'\)\.GetField\(\'m_enabled\'.{0,100}\'NonPublic.{0,100}Instance\'\)\.SetValue\(\[Ref\]\.Assembly\.GetType\(\'System\.Management\.Automation\.Tracing\.PSEtwLogProvider\'\)\.GetField\(\'etwProvider\'.{0,100}\'NonPublic.{0,100}Static\'\)\.GetValue\(\$null\).{0,100}0\)/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed HKLM:\
        // Reference: N/A
        $string6 = /\\\:MLKH/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed c:\\
        // Reference: N/A
        $string7 = /\\\\\:C/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string8 = /\\\\ataDmargorP\\\\\:C/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string9 = /\\\\swodniW\\\\\:C/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string10 = /\\ataDmargorP\\\:C/ nocase ascii wide
        // Description: reverse string registry pattern
        // Reference: N/A
        $string11 = /\\erawtfoS\\UCKH/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string12 = /\\swodniW\\\:C/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed whoami
        // Reference: N/A
        $string13 = "=imaohw" nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed net user
        // Reference: N/A
        $string14 = "=resu ten" nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string15 = "Add-MpPreference -DisableBehaviorMonitoring True" nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string16 = "Add-MpPreference -DisableBehaviourMonitoring True" nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string17 = "Add-MpPreference -DisDisableRealtimeMonitoring True" nocase ascii wide
        // Description: Windows Defender evasion add an exclusion directory for your shady stuff
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string18 = "Add-MpPreference -ExclusionPath " nocase ascii wide
        // Description: Windows Defender evasion add an exclusion directory for your shady stuff
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string19 = /Add\-MpPreference\s\-ExclustionPath\sc\:\\users\\public/ nocase ascii wide
        // Description: method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync
        // Reference: https://gist.github.com/analyticsearch/7453d22d737e46657eb57c44d5cf4cbb
        $string20 = /azuread_decrypt_msol_.{0,100}\.ps1/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string21 = /cilbuP\\\\sresU\\\\\:C/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed strings
        // Reference: N/A
        $string22 = /cilbuP\\sresU\\\:C/ nocase ascii wide
        // Description: likely associated with a PowerShell-based exploit kit such as PowerSploit or Empire
        // Reference: N/A
        $string23 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C\s.{0,100}\\temp/ nocase ascii wide
        // Description: Command to get the list of accounts with PrincipalsAllowedToDelegateToAccount (used to exploit Bronze Bit Attack)
        // Reference: N/A
        $string24 = /Get\-ADComputer\s.{0,100}\s\-Properties\sPrincipalsAllowedToDelegateToAccount/ nocase ascii wide
        // Description: Disable HA first before encrypt anything
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string25 = /Get\-Cluster\|Set\-Cluster\s\-HAEnabled\:\$false\s\-DrsEnabled\:\$false/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string26 = /http\:\/\/.{0,100}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string27 = /https\:\/\/.{0,100}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string28 = /Import\-Module\s.{0,100}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
        // Description: propagation of ACL changes on the 'AdminSDHolder' container. which can be used to maintain unauthorized access or escalate privileges in the targeted environment. The 'AdminSDHolder' container plays a crucial role in managing the security of protected groups in Active Directory. and forcing ACL changes to propagate may lead to unintended security consequences.
        // Reference: https://github.com/theyoge/AD-Pentesting-Tools/blob/main/Invoke-SDPropagator.ps1
        $string29 = "Invoke-SDPropagator" nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed powershell
        // Reference: N/A
        $string30 = "llehsrewop" nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string31 = /New\-ItemProperty\s.{0,100}\s\\"EnableModuleLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string32 = /New\-ItemProperty\s.{0,100}\s\\"EnableScriptBlockLogging\\"\s\-PropertyType\sDWord\s\-Value\s0/ nocase ascii wide
        // Description: deployment of a payload through a PowerShell stager using bits to download
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string33 = /powershell\.exe\s\-nop\s\-c\s\\"start\-job\s.{0,100}Import\-Module\sBitsTransfer.{0,100}\$env\:temp.{0,100}GetRandomFileName\(\).{0,100}Start\-BitsTransfer\s\-Source\s\'http.{0,100}Remove\-Item.{0,100}Receive\-Job/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string34 = /reg\sadd\s.{0,100}\sEnableModuleLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string35 = /reg\sadd\s.{0,100}\sEnableScriptBlockLogging\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: Delete powershell history
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string36 = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath/ nocase ascii wide
        // Description: the threat actor deleted the SD value within the Tree registry path (hide scheduled task creation)
        // Reference: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        $string37 = /Remove\-ItemProperty\s.{0,100}HKLM\:\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,100}\s\-Name\s.{0,100}SD/ nocase ascii wide
        // Description: removing powershell console logging to avoid detection
        // Reference: N/A
        $string38 = "Remove-Module -Name PsReadline" nocase ascii wide
        // Description: Defense evasion technique
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string39 = /rundll32\.exe\sC\:\\Users\\Public\\/ nocase ascii wide
        // Description: credential dumping activity
        // Reference: https://www.trendmicro.com/en_us/research/22/g/analyzing-penetration-testing-tools-that-threat-actors-use-to-br.html
        $string40 = /rundll32\.exe\sC\:\\windows\\System32\\comsvcs\.dll\sMiniDump\s\(Get\-Process\slsass\)\.id/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string41 = /Set\-ItemProperty\s.{0,100}\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string42 = /Set\-ItemProperty\s.{0,100}\s\\"EnableScriptBlockLogging\\"\s\-Value\s0/ nocase ascii wide
        // Description: disable powershell logging
        // Reference: N/A
        $string43 = /Set\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\"\s\-Name\s\\"EnableModuleLogging\\"\s\-Value\s0/ nocase ascii wide
        // Description: Windows Defender evasion add an exclusion directory for your shady stuff
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string44 = /Set\-MpPreference\s\-ExclusionPath\s.{0,100}\s\-DisableRealtimeMonitoring/ nocase ascii wide
        // Description: removing powershell console logging to avoid detection
        // Reference: N/A
        $string45 = "Set-PSReadlineOption -HistorySaveStyle SaveNothing" nocase ascii wide
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
