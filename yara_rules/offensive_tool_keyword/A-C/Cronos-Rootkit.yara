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
        $string1 = /\/Cronos\-Rootkit/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string2 = /Cronos\sRootkit\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string3 = /CronosDebugger\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string4 = /CronosRootkit\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string5 = /Rootkit\.cpp/ nocase ascii wide

    condition:
        any of them
}