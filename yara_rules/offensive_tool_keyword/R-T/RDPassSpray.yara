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
        $string1 = /.{0,1000}\/RDPassSpray\.git.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string2 = /.{0,1000}RDPassSpray\..{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string3 = /.{0,1000}RDPassSpray\.csv.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string4 = /.{0,1000}RDPassSpray\.py.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string5 = /.{0,1000}RDPassSpray\-master.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string6 = /.{0,1000}xFreed0m\/RDPassSpray.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string7 = /.{0,1000}xfreerdp\s\/v.{0,1000}SOCtest.{0,1000}AllLegitHere.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
