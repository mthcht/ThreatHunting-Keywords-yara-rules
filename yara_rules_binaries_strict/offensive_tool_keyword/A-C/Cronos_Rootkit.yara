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
        $string1 = "- Cronos rootkit debugger -" nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string2 = "/Cronos-Rootkit" nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string3 = "/Cronos-Rootkit/" nocase ascii wide
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
        $string11 = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string12 = "1d9b4121c2dbc17a4db31341da2097cd430a61201c57185a42fb687f22f704eb" nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string13 = "6f7949ffcf1b9bce2ab2301e6a75a4ba8690ea3434b74bd6c3ba0e9aca6d5d04" nocase ascii wide
        // Description: Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // Reference: https://github.com/XaFF-XaFF/Cronos-Rootkit
        $string14 = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
