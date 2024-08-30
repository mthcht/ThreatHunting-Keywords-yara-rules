rule keywa7
{
    meta:
        description = "Detection patterns for the tool 'keywa7' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keywa7"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string1 = /\.exe\s\-\-lhost\s127\.0\.0\.1\s\-\-lport\s.{0,1000}\s\-\-rhost\s/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string2 = /\/keywa7\/releases\/download\// nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string3 = /2d171b19906b039677a1213f32d27a9e1e4a0b96e9e071f7a8e8bd8a72e46243/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string4 = /571e01606bbaaab8febd88396cb3dd97eb8e883e6597d6a881f8c736eff5a05d/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string5 = /5c2a6754f5b9e92a49dfb22ce0644d0e4afaecc5b7a8d7e4714dfb578917c7d8/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string6 = /c7c2b1295dbc6b5b13330310465c771108fdeff7e7b37447bc449f6c535cfa62/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string7 = /d5aa5ef1208264ae918f0e285d358189f66d1166093657f0240a762220bd6a74/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string8 = /fb74046f994a179d004abc1f9a6a00ffa8867dc011d2e2e9ca432fe9225227c2/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string9 = /keywa7\/keywa7/ nocase ascii wide

    condition:
        any of them
}
