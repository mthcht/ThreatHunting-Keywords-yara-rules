rule lsass
{
    meta:
        description = "Detection patterns for the tool 'lsass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump LSASS memory through a process snapshot (-r) avoiding interacting with it directly
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string1 = /lsass\.dmp/ nocase ascii wide

    condition:
        any of them
}
