rule expl_bin
{
    meta:
        description = "Detection patterns for the tool 'expl-bin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expl-bin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: some of my modified exploits and some scripts.
        // Reference: https://github.com/sailay1996/expl-bin
        $string1 = /expl\-bin/ nocase ascii wide

    condition:
        any of them
}
