rule SharpUnhooker
{
    meta:
        description = "Detection patterns for the tool 'SharpUnhooker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUnhooker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# Based Universal API Unhooker
        // Reference: https://github.com/GetRektBoy724/SharpUnhooker
        $string1 = /.{0,1000}\/SharpUnhooker\.git.{0,1000}/ nocase ascii wide
        // Description: C# Based Universal API Unhooker
        // Reference: https://github.com/GetRektBoy724/SharpUnhooker
        $string2 = /.{0,1000}GetRektBoy724\/SharpUnhooker.{0,1000}/ nocase ascii wide
        // Description: C# Based Universal API Unhooker
        // Reference: https://github.com/GetRektBoy724/SharpUnhooker
        $string3 = /.{0,1000}SharpUnhooker\..{0,1000}/ nocase ascii wide
        // Description: C# Based Universal API Unhooker
        // Reference: https://github.com/GetRektBoy724/SharpUnhooker
        $string4 = /.{0,1000}SharpUnhooker\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
