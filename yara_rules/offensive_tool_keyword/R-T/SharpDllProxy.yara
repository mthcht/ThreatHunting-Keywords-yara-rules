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
        $string1 = /\s\-\-dll\s.{0,1000}\s\-\-payload\s/ nocase ascii wide
        // Description: Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // Reference: https://github.com/Flangvik/SharpDllProxy
        $string2 = /676E89F3\-4785\-477A\-BA1C\-B30340F598D5/ nocase ascii wide
        // Description: Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // Reference: https://github.com/Flangvik/SharpDllProxy
        $string3 = /7a8cabbb37d569b2d9af56a4a11bb83dc5bb839c3d4a3ea05252e20e2d0c3a45/ nocase ascii wide
        // Description: Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // Reference: https://github.com/Flangvik/SharpDllProxy
        $string4 = /SharpDllProxy/ nocase ascii wide

    condition:
        any of them
}
