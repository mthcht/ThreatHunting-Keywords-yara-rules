rule EDR_Detector
{
    meta:
        description = "Detection patterns for the tool 'EDR_Detector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDR_Detector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string1 = /\/EDR_Detector\.git/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string2 = /\/EDR_Detector\.rs/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string3 = /\\EDR_Detector\.rs/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string4 = /EDR\sDetector\sby\strickster0/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string5 = /EDR_Detection\.exe/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string6 = /EDR_Detector\.7z/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string7 = /EDR_Detector\-master/ nocase ascii wide
        // Description: detect EDR agents on a machine
        // Reference: https://github.com/trickster0/EDR_Detector
        $string8 = /trickster0\/EDR_Detector/ nocase ascii wide

    condition:
        any of them
}
