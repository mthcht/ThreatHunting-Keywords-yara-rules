rule Hash_Buster
{
    meta:
        description = "Detection patterns for the tool 'Hash-Buster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hash-Buster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hash cracking tool 
        // Reference: https://github.com/s0md3v/Hash-Buster
        $string1 = /Hash\-Buster/ nocase ascii wide

    condition:
        any of them
}
