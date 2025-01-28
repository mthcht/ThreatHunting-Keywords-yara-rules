rule SharpMove
{
    meta:
        description = "Detection patterns for the tool 'SharpMove' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMove"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\.exe\saction\=dcom\scomputername\=.{0,100}\scommand\=.{0,100}\sthrow\=wmi\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string3 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string4 = /\/SharpMove\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string6 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string7 = /\\SharpMove\.sln/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string8 = "0xthirteen/SharpMove" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string9 = "4592e0848e4929ac2b6ba4593f8cbfe09f52ce6ca4206ce52087a31073903645" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string10 = "6093461c4db41a15fefc85a28e35a9e359d0e9452bbfd36ce1fbe7aa31e1f4f0" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string11 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = "'Product'>SharpMove" nocase ascii wide
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
