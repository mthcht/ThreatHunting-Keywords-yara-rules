rule portscan
{
    meta:
        description = "Detection patterns for the tool 'portscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "portscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple TCP and UDP portscanner written in Go
        // Reference: https://github.com/zs5460/portscan
        $string1 = /.{0,1000}portscan.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
