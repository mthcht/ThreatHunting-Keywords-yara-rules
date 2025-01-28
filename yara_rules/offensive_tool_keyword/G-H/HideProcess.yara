rule HideProcess
{
    meta:
        description = "Detection patterns for the tool 'HideProcess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HideProcess"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: process injection rootkit
        // Reference: https://github.com/landhb/HideProcess
        $string1 = "landhb/HideProcess" nocase ascii wide

    condition:
        any of them
}
