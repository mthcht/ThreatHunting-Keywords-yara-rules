rule iodine
{
    meta:
        description = "Detection patterns for the tool 'iodine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iodine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://linux.die.net/man/8/iodine
        $string1 = /iodine\s\-/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://linux.die.net/man/8/iodine
        $string2 = /iodined\s\-/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://linux.die.net/man/8/iodine
        $string3 = /ionide\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://linux.die.net/man/8/iodine
        $string4 = /ionided\s/ nocase ascii wide

    condition:
        any of them
}