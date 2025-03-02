rule nopaste_net
{
    meta:
        description = "Detection patterns for the tool 'nopaste.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopaste.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string1 = /curl.{0,1000}nopaste\.net/
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string2 = /docker\srun\s.{0,1000}\/\.config\/pcopy/
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string3 = /https\:\/\/nopaste\.net\// nocase ascii wide
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string4 = /IEX.{0,1000}nopaste\.net/ nocase ascii wide
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string5 = /IWR.{0,1000}nopaste\.net/ nocase ascii wide
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string6 = /nc\s\-N\snopaste\.net\s/
        // Description: nopaste.net is a temporary file host - nopaste and clipboard across machines. You can upload files or text and share the link with others - abused by attackers for collection and data exfiltration
        // Reference: https://www.shellhub.io/
        $string7 = /nopaste\.net.{0,1000}IWR/ nocase ascii wide

    condition:
        any of them
}
