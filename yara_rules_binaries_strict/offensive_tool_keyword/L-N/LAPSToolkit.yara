rule LAPSToolkit
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\sLAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string2 = /\/LAPSToolkit\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\/LAPSToolkit\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\\LAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string5 = "cd05b7676886e560400643e3852e64483cee95f4741ec8a930c7b1f68479835a" nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string6 = "Find-LAPSDelegatedGroups " nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string7 = "LAPSToolkit" nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string8 = /LAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string9 = "leoloobeek/LAPSToolkit" nocase ascii wide
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
