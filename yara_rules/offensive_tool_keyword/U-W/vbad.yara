rule vbad
{
    meta:
        description = "Detection patterns for the tool 'vbad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vbad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string1 = /.{0,1000}Pepitoh.{0,1000}VBad.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
