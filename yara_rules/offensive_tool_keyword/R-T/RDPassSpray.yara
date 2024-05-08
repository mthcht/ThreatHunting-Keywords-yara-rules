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
        $string2 = /62db3e73826eb5cd8b14f3b54e7c476d423f28c0d4e467632fcacf338c250301/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string3 = /dafthack\/RDPSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string4 = /fake_hostnames\(hostnames_list\)/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string5 = /RDPassSpray\..{0,1000}\.log/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string6 = /RDPassSpray\.csv/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string7 = /RDPassSpray\.py/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string8 = /RDPassSpray\-main/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string9 = /RDPassSpray\-master/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string10 = /xFreed0m\/RDPassSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying using RDP
        // Reference: https://github.com/xFreed0m/RDPassSpray
        $string11 = /xfreerdp\s\/v.{0,1000}SOCtest.{0,1000}AllLegitHere/ nocase ascii wide

    condition:
        any of them
}
