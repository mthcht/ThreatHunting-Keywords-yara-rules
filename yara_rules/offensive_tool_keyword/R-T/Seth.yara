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
        $string1 = /.{0,1000}\.\/seth\.sh\s.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string2 = /.{0,1000}\.py\s.{0,1000}\s\s\-\-fake\-server.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string3 = /.{0,1000}arpspoof\s\-i\s.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string4 = /.{0,1000}Server\senforces\sNLA\;\sswitching\sto\s\'fake\sserver\'\smode.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string5 = /.{0,1000}Seth\sby\sSySS\sGmbH.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string6 = /.{0,1000}seth\.py\s.{0,1000}\s\-j\sINJECT.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string7 = /.{0,1000}Seth\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Perform a MitM attack and extract clear text credentials from RDP connections
        // Reference: https://github.com/SySS-Research/Seth
        $string8 = /.{0,1000}SySS\-Research\/Seth.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
