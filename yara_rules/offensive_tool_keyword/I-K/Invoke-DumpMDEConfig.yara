rule Invoke_DumpMDEConfig
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DumpMDEConfig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DumpMDEConfig"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string1 = /\[\+\]\sDefender\sConfig\sDumped\sto\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string2 = /\[\+\]\sDumped\sAllowed\sThreats\sto\s.{0,1000}\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string3 = /\[\+\]\sDumped\sExclusion\sPaths\sto\sExclusionPaths\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string4 = /\[\+\]\sDumped\sExploit\sGuard\sProtection\sHistory/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string5 = /\[\+\]\sDumped\sFirewall\sExclusions\sto\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string6 = /\[\+\]\sDumped\sProtection\sHistory\sto\sProtectionHistory\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string7 = /\[\+\]\sDumping\sDefender\sExcluded\sPaths/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string8 = /\[\+\]\sDumping\sDefender\sProtection\sHistory/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string9 = /\[\+\]\sDumping\sEnabled\sASR\sRules/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string10 = /\[System\[Provider\[\@Name\=\'Microsoft\-Windows\-Windows\sDefender\'\]\sand\s\(EventID\=5007\)\]\]/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string11 = /\\ExploitGuardProtectionHistory\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string12 = /78a098cf3b91a354d6425bb5c08af4a0cc137a71bec4ad44707d864e263a4384/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string13 = /Invoke\-DumpMDEConfig/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string14 = /Query\-ExploitGuardProtectionHistory\s/ nocase ascii wide

    condition:
        any of them
}
