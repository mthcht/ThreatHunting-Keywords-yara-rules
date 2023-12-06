rule Sharp_Suite
{
    meta:
        description = "Detection patterns for the tool 'Sharp-Suite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sharp-Suite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string1 = /FuzzySecurity\/Sharp\-Suite/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string2 = /Londor\.exe\s\-t\sCoverage/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string3 = /Londor\.exe\s\-t\sScript/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string4 = /Sharp\-Suite\.git/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string5 = /UrbanBishop\.exe/ nocase ascii wide

    condition:
        any of them
}
