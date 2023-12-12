rule set
{
    meta:
        description = "Detection patterns for the tool 'set' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "set"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Does not write any of the current session to the history log
        // Reference: N/A
        $string1 = /set\s\+o\shistory/ nocase ascii wide

    condition:
        any of them
}
