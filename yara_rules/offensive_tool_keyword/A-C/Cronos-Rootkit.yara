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
        $string1 = /\-\sCronos\srootkit\sdebugger\s\-/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string2 = /\/Cronos\-Rootkit/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string3 = /\/Cronos\-Rootkit\// nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string4 = /\/Cronos\-x64\.zip/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string5 = /\\\\\\\\\.\\\\Cronos/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string6 = /\\Cronos\sRootkit\.sln/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string7 = /\\Cronos\sRootkit\\/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string8 = /\\CronosDebugger\.vcxproj/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string9 = /\\Cronos\-x64\.zip/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string10 = /\\Rootkit\.cpp/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string11 = /05B4EB7F\-3D59\-4E6A\-A7BC\-7C1241578CA7/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string12 = /1d9b4121c2dbc17a4db31341da2097cd430a61201c57185a42fb687f22f704eb/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string13 = /6f7949ffcf1b9bce2ab2301e6a75a4ba8690ea3434b74bd6c3ba0e9aca6d5d04/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string14 = /940B1177\-2B8C\-48A2\-A8E7\-BF4E8E80C60F/ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string15 = /Cronos\sRootkit\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string16 = /CronosDebugger\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string17 = /CronosRootkit\./ nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string18 = /Rootkit\.cpp/ nocase ascii wide

    condition:
        any of them
}
