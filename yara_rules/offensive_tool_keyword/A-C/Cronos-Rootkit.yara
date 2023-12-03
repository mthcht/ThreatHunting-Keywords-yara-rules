rule Cronos_Rootkit
{
    meta:
        description = "Detection patterns for the tool 'Cronos-Rootkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cronos-Rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string1 = /.{0,1000}\/Cronos\-Rootkit.{0,1000}/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string2 = /.{0,1000}Cronos\sRootkit\..{0,1000}/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string3 = /.{0,1000}CronosDebugger\..{0,1000}/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string4 = /.{0,1000}CronosRootkit\..{0,1000}/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string5 = /.{0,1000}Rootkit\.cpp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
