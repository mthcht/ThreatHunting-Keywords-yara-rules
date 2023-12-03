rule DLL_Spoofer
{
    meta:
        description = "Detection patterns for the tool 'DLL-Spoofer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLL-Spoofer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string1 = /.{0,1000}\/DLL\-Spoofer\.git.{0,1000}/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string2 = /.{0,1000}\\spoof\.py.{0,1000}/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string3 = /.{0,1000}DLL\-Spoofer\-main.{0,1000}/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string4 = /.{0,1000}MitchHS\/DLL\-Spoofer.{0,1000}/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string5 = /.{0,1000}spoof\.py\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
