rule VoidCrypt
{
    meta:
        description = "Detection patterns for the tool 'VoidCrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VoidCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string1 = /fuckyoufuckyoufuckyoufuckyoufuckyou/ nocase ascii wide

    condition:
        any of them
}
