rule obfy
{
    meta:
        description = "Detection patterns for the tool 'obfy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "obfy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tiny C++ obfuscation framework
        // Reference: https://github.com/fritzone/obfy
        $string1 = /\/fritzone\/obfy/ nocase ascii wide
        // Description: A tiny C++ obfuscation framework
        // Reference: https://github.com/fritzone/obfy
        $string2 = /\\obfy\-1\.0\.zip/ nocase ascii wide

    condition:
        any of them
}
