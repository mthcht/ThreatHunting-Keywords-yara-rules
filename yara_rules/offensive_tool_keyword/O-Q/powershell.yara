rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: powershell obfuscations techniques observed by malwares - reversed whoami
        // Reference: N/A
        $string1 = /.{0,1000}\simaohw.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed net user
        // Reference: N/A
        $string2 = /.{0,1000}\sresu\sten.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed http://
        // Reference: N/A
        $string3 = /.{0,1000}\/\/:ptth.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed https://
        // Reference: N/A
        $string4 = /.{0,1000}\/\/:sptth.{0,1000}/ nocase ascii wide
        // Description: impair the defenses of the targeted system by disabling ETW logging for PowerShell. This can make it difficult for security teams to monitor and analyze PowerShell activities on the system potentially allowing adversaries to perform malicious actions without being detected
        // Reference: N/A
        $string5 = /.{0,1000}\[Reflection\.Assembly\]::LoadWithPartialName\(\'System\.Core\'\)\.GetType\(\'System\.Diagnostics\.Eventing\.EventProvider\'\)\.GetField\(\'m_enabled\'.{0,1000}\'NonPublic.{0,1000}Instance\'\)\.SetValue\(\[Ref\]\.Assembly\.GetType\(\'System\.Management\.Automation\.Tracing\.PSEtwLogProvider\'\)\.GetField\(\'etwProvider\'.{0,1000}\'NonPublic.{0,1000}Static\'\)\.GetValue\(\$null\).{0,1000}0\).{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed HKLM:\
        // Reference: N/A
        $string6 = /.{0,1000}\\:MLKH.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed c:\\
        // Reference: N/A
        $string7 = /.{0,1000}\\\\:C.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed whoami
        // Reference: N/A
        $string8 = /.{0,1000}\=imaohw.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed net user
        // Reference: N/A
        $string9 = /.{0,1000}\=resu\sten.{0,1000}/ nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string10 = /.{0,1000}Add\-MpPreference\s\-DisableBehaviorMonitoring\sTrue.{0,1000}/ nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string11 = /.{0,1000}Add\-MpPreference\s\-DisableBehaviourMonitoring\sTrue.{0,1000}/ nocase ascii wide
        // Description: Windows defender disable protection
        // Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
        $string12 = /.{0,1000}Add\-MpPreference\s\-DisDisableRealtimeMonitoring\sTrue.{0,1000}/ nocase ascii wide
        // Description: Windows Defender evasion add an exclusion directory for your shady stuff
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string13 = /.{0,1000}Add\-MpPreference\s\-ExclusionPath\s.{0,1000}/ nocase ascii wide
        // Description: Windows Defender evasion add an exclusion directory for your shady stuff
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string14 = /.{0,1000}Add\-MpPreference\s\-ExclustionPath\sc:\\users\\public.{0,1000}/ nocase ascii wide
        // Description: method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync
        // Reference: https://gist.github.com/analyticsearch/7453d22d737e46657eb57c44d5cf4cbb
        $string15 = /.{0,1000}azuread_decrypt_msol_.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Command to get the list of accounts with PrincipalsAllowedToDelegateToAccount (used to exploit Bronze Bit Attack)
        // Reference: N/A
        $string16 = /.{0,1000}Get\-ADComputer\s.{0,1000}\s\-Properties\sPrincipalsAllowedToDelegateToAccount.{0,1000}/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string17 = /.{0,1000}http:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll.{0,1000}/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string18 = /.{0,1000}https:\/\/.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll.{0,1000}/ nocase ascii wide
        // Description: redteam technique - import the ActiveDirectory module without the need to install it on the current computer - the dll has been extracted from a Windows 10 x64 with RSAT installed
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/ActiveDirectory/Bruteforce.ps1
        $string19 = /.{0,1000}Import\-Module\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll.{0,1000}/ nocase ascii wide
        // Description: propagation of ACL changes on the 'AdminSDHolder' container. which can be used to maintain unauthorized access or escalate privileges in the targeted environment. The 'AdminSDHolder' container plays a crucial role in managing the security of protected groups in Active Directory. and forcing ACL changes to propagate may lead to unintended security consequences.
        // Reference: https://github.com/theyoge/AD-Pentesting-Tools/blob/main/Invoke-SDPropagator.ps1
        $string20 = /.{0,1000}Invoke\-SDPropagator.{0,1000}/ nocase ascii wide
        // Description: powershell obfuscations techniques observed by malwares - reversed powershell
        // Reference: N/A
        $string21 = /.{0,1000}llehsrewop.{0,1000}/ nocase ascii wide
        // Description: Delete powershell history
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string22 = /.{0,1000}Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath.{0,1000}/ nocase ascii wide
        // Description: the threat actor deleted the SD value within the Tree registry path (hide scheduled task creation)
        // Reference: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        $string23 = /.{0,1000}Remove\-ItemProperty\s.{0,1000}HKLM:\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\s\-Name\s.{0,1000}SD.{0,1000}/ nocase ascii wide
        // Description: deployment of a payload through a PowerShell stager using bits to download
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string24 = /powershell\.exe\s\-nop\s\-c\s\"start\-job\s.{0,1000}Import\-Module\sBitsTransfer.{0,1000}\$env:temp.{0,1000}GetRandomFileName\(\).{0,1000}Start\-BitsTransfer\s\-Source\s\'http.{0,1000}Remove\-Item.{0,1000}Receive\-Job.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
