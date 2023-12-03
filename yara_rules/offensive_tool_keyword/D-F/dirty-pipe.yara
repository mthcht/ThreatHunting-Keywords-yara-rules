rule dirty_pipe
{
    meta:
        description = "Detection patterns for the tool 'dirty-pipe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirty-pipe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC exploitation for dirty pipe vulnerability
        // Reference: https://github.com/0xIronGoat/dirty-pipe
        $string1 = /.{0,1000}\.\/exploit\s\/etc\/passwd\s1\s.{0,1000}cat\s\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: POC exploitation for dirty pipe vulnerability
        // Reference: https://github.com/0xIronGoat/dirty-pipe
        $string2 = /.{0,1000}\/0xIronGoat\/dirty\-pipe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
