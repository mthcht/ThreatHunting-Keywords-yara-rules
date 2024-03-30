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
        $string1 = /taskkill\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
        // Description: evade EDR/AV by repairing with msiexec and killing the process
        // Reference: https://badoption.eu/blog/2024/03/23/cortex.html
        $string2 = /taskkill\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide
        // Description: killing lsass process
        // Reference: https://x.com/malmoeb/status/1741114854037987437
        $string3 = /taskkill\.exe\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
        // Description: evade EDR/AV by repairing with msiexec and killing the process
        // Reference: https://badoption.eu/blog/2024/03/23/cortex.html
        $string4 = /taskkill\.exe\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide

    condition:
        any of them
}
