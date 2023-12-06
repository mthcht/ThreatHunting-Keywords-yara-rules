rule DesertNut
{
    meta:
        description = "Detection patterns for the tool 'DesertNut' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DesertNut"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DesertNut is a proof-of-concept for code injection using subclassed window callbacks (more commonly known as PROPagate)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/DesertNut
        $string1 = /DesertNut\.csproj/ nocase ascii wide
        // Description: DesertNut is a proof-of-concept for code injection using subclassed window callbacks (more commonly known as PROPagate)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/DesertNut
        $string2 = /DesertNut\.exe/ nocase ascii wide
        // Description: DesertNut is a proof-of-concept for code injection using subclassed window callbacks (more commonly known as PROPagate)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/DesertNut
        $string3 = /DesertNut\.sln/ nocase ascii wide
        // Description: DesertNut is a proof-of-concept for code injection using subclassed window callbacks (more commonly known as PROPagate)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/DesertNut
        $string4 = /DesertNut_h\.cs/ nocase ascii wide

    condition:
        any of them
}
