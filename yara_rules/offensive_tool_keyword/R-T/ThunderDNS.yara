rule ThunderDNS
{
    meta:
        description = "Detection patterns for the tool 'ThunderDNS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderDNS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string1 = /.{0,1000}\/ThunderDNS.{0,1000}/ nocase ascii wide
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string2 = /.{0,1000}proxy\.py\s\-\-dns\s.{0,1000}\s\-\-dns_port\s\s.{0,1000}\s\-\-clients.{0,1000}/ nocase ascii wide
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string3 = /.{0,1000}ThunderDNS.{0,1000}\.php.{0,1000}/ nocase ascii wide
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string4 = /.{0,1000}ThunderDNS.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string5 = /.{0,1000}ThunderDNS.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: This tool can forward TCP traffic over DNS protocol
        // Reference: https://github.com/fbkcs/ThunderDNS
        $string6 = /.{0,1000}ThunderDNS\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
