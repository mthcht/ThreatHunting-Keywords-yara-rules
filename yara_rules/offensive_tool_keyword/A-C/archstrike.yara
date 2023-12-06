rule archstrike
{
    meta:
        description = "Detection patterns for the tool 'archstrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "archstrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Arch Linux repo containing lots of exploitation tools for pentesters
        // Reference: https://archstrike.org/
        $string1 = /ArchStrike/ nocase ascii wide

    condition:
        any of them
}
