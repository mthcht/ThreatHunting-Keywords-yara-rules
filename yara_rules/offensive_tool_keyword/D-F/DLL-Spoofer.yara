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
        $string1 = /\/DLL\-Spoofer\.git/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string2 = /\\spoof\.py/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string3 = /DLL\-Spoofer\-main/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string4 = /MitchHS\/DLL\-Spoofer/ nocase ascii wide
        // Description: POC for a DLL spoofer to determine DLL Hijacking
        // Reference: https://github.com/MitchHS/DLL-Spoofer
        $string5 = /spoof\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
