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
        $string1 = /.{0,1000}FuzzySecurity\/Sharp\-Suite.{0,1000}/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string2 = /.{0,1000}Londor\.exe\s\-t\sCoverage.{0,1000}/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string3 = /.{0,1000}Londor\.exe\s\-t\sScript.{0,1000}/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string4 = /.{0,1000}Sharp\-Suite\.git.{0,1000}/ nocase ascii wide
        // Description: C# offensive tools
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite
        $string5 = /.{0,1000}UrbanBishop\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
