rule export
{
    meta:
        description = "Detection patterns for the tool 'export' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "export"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1 = /export\sHISTFILE\=\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3 = /export\sHISTSIZE\=0/ nocase ascii wide

    condition:
        any of them
}
