rule SCCMVNC
{
    meta:
        description = "Detection patterns for the tool 'SCCMVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCCMVNC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to modify SCCM remote control settings on the client machine - enabling remote control without permission prompts or notifications. This can be done without requiring access to SCCM server.
        // Reference: https://github.com/netero1010/SCCMVNC
        $string1 = /\/SCCMVNC\.git/ nocase ascii wide
        // Description: A tool to modify SCCM remote control settings on the client machine - enabling remote control without permission prompts or notifications. This can be done without requiring access to SCCM server.
        // Reference: https://github.com/netero1010/SCCMVNC
        $string2 = "b4d2e7159b1707d9355ac8699897c55441a25afebf66b4f47087b34d5e4994cb" nocase ascii wide
        // Description: A tool to modify SCCM remote control settings on the client machine - enabling remote control without permission prompts or notifications. This can be done without requiring access to SCCM server.
        // Reference: https://github.com/netero1010/SCCMVNC
        $string3 = "netero1010/SCCMVNC" nocase ascii wide
        // Description: A tool to modify SCCM remote control settings on the client machine - enabling remote control without permission prompts or notifications. This can be done without requiring access to SCCM server.
        // Reference: https://github.com/netero1010/SCCMVNC
        $string4 = /SCCMVNC\.exe/ nocase ascii wide

    condition:
        any of them
}
