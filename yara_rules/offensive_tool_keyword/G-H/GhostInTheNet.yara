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
        $string1 = /\/GhostInTheNet\.git/
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string2 = /\/GhostInTheNet\.sh/
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string3 = "/GhostInTheNet-master"
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string4 = /\/tmp\/host\.ghost/
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string5 = /\/tmp\/mac\.ghost/
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string6 = "GhostInTheNet off"
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string7 = "GhostInTheNet on"
        // Description: Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
        // Reference: https://github.com/cryptolok/GhostInTheNet
        $string8 = /GhostInTheNet\.sh\s/

    condition:
        any of them
}
