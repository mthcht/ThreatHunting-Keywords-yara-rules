rule FourEye
{
    meta:
        description = "Detection patterns for the tool 'FourEye' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FourEye"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string1 = /\sBypassFramework\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string2 = /\sdarkexe\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string3 = /\sUUID_bypass\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string4 = /\/BypassFramework\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string5 = /\/darkexe\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string6 = /\/FourEye\.git/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string7 = /\/module\/darkexe\// nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string8 = /\/root\/shellcode\.c/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string9 = /\/root\/shellcode\.cpp/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string10 = /\/root\/shellcode\.exe/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string11 = /\/UUID_bypass\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string12 = /\\darkexe\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string13 = /\\UUID_bypass\.py/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string14 = /FourEye\(shellcode_bypass/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string15 = /FourEye\-main/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string16 = /lengjibo\/FourEye/ nocase ascii wide

    condition:
        any of them
}
