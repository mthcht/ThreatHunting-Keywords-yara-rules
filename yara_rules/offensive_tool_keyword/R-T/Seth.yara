rule Seth
{
    meta:
        description = "Detection patterns for the tool 'Seth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Seth"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string1 = /\.\/seth\.sh\s.{0,1000}\s/
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string2 = /\.py\s.{0,1000}\s\s\-\-fake\-server/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string3 = "arpspoof -i " nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string4 = "Server enforces NLA; switching to 'fake server' mode" nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string5 = "Seth by SySS GmbH" nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string6 = /seth\.py\s.{0,1000}\s\-j\sINJECT/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string7 = /Seth\-master\.zip/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string8 = "SySS-Research/Seth" nocase ascii wide

    condition:
        any of them
}
