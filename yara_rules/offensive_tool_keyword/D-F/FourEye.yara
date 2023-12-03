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
        $string1 = /.{0,1000}\sBypassFramework\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string2 = /.{0,1000}\sdarkexe\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string3 = /.{0,1000}\sUUID_bypass\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string4 = /.{0,1000}\/BypassFramework\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string5 = /.{0,1000}\/darkexe\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string6 = /.{0,1000}\/FourEye\.git.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string7 = /.{0,1000}\/module\/darkexe\/.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string8 = /.{0,1000}\/root\/shellcode\.c.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string9 = /.{0,1000}\/root\/shellcode\.cpp.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string10 = /.{0,1000}\/root\/shellcode\.exe.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string11 = /.{0,1000}\/UUID_bypass\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string12 = /.{0,1000}\\darkexe\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string13 = /.{0,1000}\\UUID_bypass\.py.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string14 = /.{0,1000}FourEye\(shellcode_bypass.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string15 = /.{0,1000}FourEye\-main.{0,1000}/ nocase ascii wide
        // Description: AV Evasion Tool
        // Reference: https://github.com/lengjibo/FourEye
        $string16 = /.{0,1000}lengjibo\/FourEye.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
