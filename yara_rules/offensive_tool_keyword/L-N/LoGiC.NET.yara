rule LoGiC_NET
{
    meta:
        description = "Detection patterns for the tool 'LoGiC.NET' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LoGiC.NET"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A more advanced free and open .NET obfuscator using dnlib
        // Reference: https://github.com/AnErrupTion/LoGiC.NET
        $string1 = /.{0,1000}AnErrupTion\/LoGiC\.NET.{0,1000}/ nocase ascii wide
        // Description: A more advanced free and open .NET obfuscator using dnlib
        // Reference: https://github.com/AnErrupTion/LoGiC.NET
        $string2 = /.{0,1000}LoGiC\.NET\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
