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
        $string1 = /.{0,1000}AtlasC2.{0,1000}APIModels.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string2 = /.{0,1000}AtlasC2.{0,1000}Client.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string3 = /.{0,1000}AtlasC2.{0,1000}implant.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string4 = /.{0,1000}AtlasC2.{0,1000}TeamServer.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string5 = /.{0,1000}AtlasC2\.exe.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string6 = /.{0,1000}AtlasC2b\.exe.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string7 = /.{0,1000}AtlasC2b\.sln.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string8 = /.{0,1000}AtlasImplant\.yar.{0,1000}/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string9 = /.{0,1000}Gr1mmie\/AtlasC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
