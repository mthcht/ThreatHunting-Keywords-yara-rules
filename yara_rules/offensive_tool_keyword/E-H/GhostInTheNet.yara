rule GhostInTheNet
{
    meta:
        description = "Detection patterns for the tool 'GhostInTheNet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostInTheNet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string1 = /\/GhostInTheNet\.git/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string2 = /\/GhostInTheNet\.sh/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string3 = /\/GhostInTheNet\-master/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string4 = /\/tmp\/host\.ghost/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string5 = /\/tmp\/mac\.ghost/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string6 = /GhostInTheNet\soff/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string7 = /GhostInTheNet\son/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string8 = /GhostInTheNet\.sh\s/ nocase ascii wide

    condition:
        any of them
}
