rule taskkill
{
    meta:
        description = "Detection patterns for the tool 'taskkill' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "taskkill"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: killing lsass process
        // Reference: https://x.com/malmoeb/status/1741114854037987437
        $string1 = /taskkill\.exe\s\/F\s\/IM\slsass\.exe/ nocase ascii wide

    condition:
        any of them
}
