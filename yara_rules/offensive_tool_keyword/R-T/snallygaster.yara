rule snallygaster
{
    meta:
        description = "Detection patterns for the tool 'snallygaster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snallygaster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Finds file leaks and other security problems on HTTP servers.snallygaster is a tool that looks for files accessible on web servers that shouldn't be public and can pose a security risk.
        // Reference: https://github.com/hannob/snallygaster
        $string1 = /snallygaster/ nocase ascii wide

    condition:
        any of them
}
