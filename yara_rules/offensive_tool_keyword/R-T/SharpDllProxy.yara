rule SharpDllProxy
{
    meta:
        description = "Detection patterns for the tool 'SharpDllProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDllProxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // Reference: https://github.com/Flangvik/SharpDllProxy
        $string1 = /\s\-\-dll\s.*\s\-\-payload\s/ nocase ascii wide
        // Description: Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // Reference: https://github.com/Flangvik/SharpDllProxy
        $string2 = /SharpDllProxy/ nocase ascii wide

    condition:
        any of them
}