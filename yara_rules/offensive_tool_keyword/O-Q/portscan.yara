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
        $string1 = /\/portscan\.git/ nocase ascii wide
        // Description: A simple TCP and UDP portscanner written in Go
        // Reference: https://github.com/zs5460/portscan
        $string2 = /\/portscan\/releases\// nocase ascii wide
        // Description: A simple TCP and UDP portscanner written in Go
        // Reference: https://github.com/zs5460/portscan
        $string3 = /57c646df3c07792d9c6e479b7faa5ccd7802dc03dc49e477534e2322cb753bf9/ nocase ascii wide
        // Description: A simple TCP and UDP portscanner written in Go
        // Reference: https://github.com/zs5460/portscan
        $string4 = /zs5460\/portscan/ nocase ascii wide

    condition:
        any of them
}
