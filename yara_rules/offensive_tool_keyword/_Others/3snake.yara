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
        $string1 = /.{0,1000}\.\/snake/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string2 = /.{0,1000}\/3snake\.git.{0,1000}/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string3 = /.{0,1000}\/passwd_tracer\.c.{0,1000}/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string4 = /.{0,1000}\/sudo_tracer\.c.{0,1000}/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string5 = /.{0,1000}\/tracers_fuzzer\.cc.{0,1000}/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string6 = /.{0,1000}3snake\-master.{0,1000}/ nocase ascii wide
        // Description: Tool for extracting information from newly spawned processes
        // Reference: https://github.com/blendin/3snake
        $string7 = /.{0,1000}blendin\/3snake.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
