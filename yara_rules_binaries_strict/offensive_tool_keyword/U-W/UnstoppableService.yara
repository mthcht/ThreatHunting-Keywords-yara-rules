rule UnstoppableService
{
    meta:
        description = "Detection patterns for the tool 'UnstoppableService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnstoppableService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string1 = "\"ServiceName = \"\"unstoppable\"" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string2 = /\/UnstoppableService\.git/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string3 = /\\UnstoppableService\.csproj/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string4 = /\\UnstoppableService\.sln/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string5 = /\\UnstoppableService\-master/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string6 = "0C117EE5-2A21-496D-AF31-8CC7F0CAAA86" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string7 = "4889b9e1fa6c34ea86e56253135093b390919aa006f8cd3fa372b410f2f1e5bf" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string8 = "8e66227e48270913e40edcabdaa2d20332572f8ca6d066737e4ae3984d66b591" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string9 = "malcomvetter/UnstoppableService" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string10 = /Provides\san\sunstoppable\sWindows\sService\sExperience\.\sLorem\sIpsum\sDolor/ nocase ascii wide
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
