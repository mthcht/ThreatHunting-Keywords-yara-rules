rule SharpPrintNightmare
{
    meta:
        description = "Detection patterns for the tool 'SharpPrintNightmare' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPrintNightmare"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# and Impacket implementation of PrintNightmare CVE-2021-1675/CVE-2021-34527
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string1 = /SharpPrintNightmare/ nocase ascii wide

    condition:
        any of them
}
