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
        $string1 = /.{0,1000}\/GhostInTheNet\.git.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string2 = /.{0,1000}\/GhostInTheNet\.sh.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string3 = /.{0,1000}\/GhostInTheNet\-master.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string4 = /.{0,1000}\/tmp\/host\.ghost.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string5 = /.{0,1000}\/tmp\/mac\.ghost.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string6 = /.{0,1000}GhostInTheNet\soff.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string7 = /.{0,1000}GhostInTheNet\son.{0,1000}/ nocase ascii wide
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string8 = /.{0,1000}GhostInTheNet\.sh\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
