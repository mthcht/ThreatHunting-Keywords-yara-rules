rule RDPassSpray
{
    meta:
        description = "Detection patterns for the tool 'RDPassSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string1 = /\/RDPassSpray\.git/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string2 = /RDPassSpray\..{0,1000}\.log/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string3 = /RDPassSpray\.csv/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string4 = /RDPassSpray\-master/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string5 = /xFreed0m\/RDPassSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string6 = /xfreerdp\s\/v.{0,1000}SOCtest.{0,1000}AllLegitHere/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string7 = /d/ nocase ascii wide

    condition:
        any of them
}
