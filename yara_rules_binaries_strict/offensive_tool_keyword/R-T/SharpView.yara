rule SharpView
{
    meta:
        description = "Detection patterns for the tool 'SharpView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string1 = /\.exe\sGet\-DomainController\s\-Domain\s.{0,100}\s\-Server\s.{0,100}\s\-Credential\s/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string2 = /\/PowerView\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\/SharpView\.exe/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string4 = /\/SharpView\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\\SharpView\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /\\SharpView\.pdb/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string7 = ">SharpView<" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = ">SharpView<" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string9 = "22A156EA-2623-45C7-8E50-E864D9FC44D3" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string10 = "Args_Invoke_Kerberoast" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string11 = "c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string12 = "e42e5cf9-be25-4011-9623-8565b193a506" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string13 = "hackbuildrepeat/SharpView" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string14 = /SharpView\.exe/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string15 = /SharpView\\SharpView/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string16 = "SharpView-master" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string17 = "tevora-threat/SharpView/" nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string18 = /using\sSharpView\.Enums/ nocase ascii wide
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
