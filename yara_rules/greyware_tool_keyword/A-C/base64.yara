rule _base64
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious base64 commands used by the offensive tool traitor and other tools
        // Reference: N/A
        $string1 = /\|\sbase64\s\-d\s/ nocase ascii wide
        // Description: suspicious base64 commands used by the offensive tool traitor and other tools
        // Reference: N/A
        $string2 = "base64 -d /tmp/" nocase ascii wide

    condition:
        any of them
}
