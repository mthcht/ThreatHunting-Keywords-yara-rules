rule mitm6
{
    meta:
        description = "Detection patterns for the tool 'mitm6' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitm6"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: performs MiTM for IPv6
        // Reference: https://github.com/fox-it/mitm6
        $string1 = /mitm6\s\-d\s/ nocase ascii wide
        // Description: performs MiTM for IPv6
        // Reference: https://github.com/fox-it/mitm6
        $string2 = /mitm6\.py/ nocase ascii wide

    condition:
        any of them
}
