rule mkdir
{
    meta:
        description = "Detection patterns for the tool 'mkdir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mkdir"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: delete bash history
        // Reference: N/A
        $string1 = /mkdir\s\~\/\.bash_history/ nocase ascii wide

    condition:
        any of them
}
