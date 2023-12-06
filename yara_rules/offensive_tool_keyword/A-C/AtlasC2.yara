rule AtlasC2
{
    meta:
        description = "Detection patterns for the tool 'AtlasC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string1 = /AtlasC2.{0,1000}APIModels/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string2 = /AtlasC2.{0,1000}Client/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string3 = /AtlasC2.{0,1000}implant/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string4 = /AtlasC2.{0,1000}TeamServer/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string5 = /AtlasC2\.exe/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string6 = /AtlasC2b\.exe/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string7 = /AtlasC2b\.sln/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string8 = /AtlasImplant\.yar/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string9 = /Gr1mmie\/AtlasC2/ nocase ascii wide

    condition:
        any of them
}
