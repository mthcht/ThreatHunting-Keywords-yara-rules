rule rdrleakdiag
{
    meta:
        description = "Detection patterns for the tool 'rdrleakdiag' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdrleakdiag"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Microsoft Windows resource leak diagnostic tool potentially dumping lsass process
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/
        $string1 = /rdrleakdiag\.exe\s\/p\s.{0,1000}\s\/o\s.{0,1000}\s\/fullmemdmp\s\/wait\s1/ nocase ascii wide

    condition:
        any of them
}
