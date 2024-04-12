rule esentutl
{
    meta:
        description = "Detection patterns for the tool 'esentutl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esentutl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: extract the AD Database
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Esentutl/
        $string1 = /esentutl\.exe\s\/y\s\/vss\s.{0,1000}\:\\windows\\ntds\\ntds\.dit/ nocase ascii wide

    condition:
        any of them
}
