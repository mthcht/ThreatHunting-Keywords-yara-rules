rule macchanger
{
    meta:
        description = "Detection patterns for the tool 'macchanger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macchanger"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: changing mac address with macchanger
        // Reference: N/A
        $string1 = /macchanger\s\-r\s/ nocase ascii wide

    condition:
        any of them
}
