rule SharpGhostTask
{
    meta:
        description = "Detection patterns for the tool 'SharpGhostTask' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGhostTask"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string1 = /\.exe\s\-\-targettask\s.{0,1000}\s\-\-targetbinary\s\s/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string2 = /\/SharpGhostTask/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string3 = /\\SharpGhostTask/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string4 = /1A8C9BD8\-1800\-46B0\-8E22\-7D3823C68366/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string5 = /SharpGhostTask\.csproj/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string6 = /SharpGhostTask\.exe/ nocase ascii wide
        // Description: registry manipulation to create scheduled tasks without triggering the usual event logs.
        // Reference: https://github.com/dmcxblue/SharpGhostTask
        $string7 = /SharpGhostTask\.sln/ nocase ascii wide

    condition:
        any of them
}
