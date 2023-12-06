rule _3snake
{
    meta:
        description = "Detection patterns for the tool '3snake' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3snake"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string1 = /\.\/snake/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string2 = /\/3snake\.git/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string3 = /\/passwd_tracer\.c/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string4 = /\/sudo_tracer\.c/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string5 = /\/tracers_fuzzer\.cc/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string6 = /3snake\-master/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string7 = /blendin\/3snake/ nocase ascii wide

    condition:
        any of them
}
