rule bash_port_scan
{
    meta:
        description = "Detection patterns for the tool 'bash port scan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash port scan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1 = /for\si\sin\s\{1\.\.65535\}/ nocase ascii wide

    condition:
        any of them
}
