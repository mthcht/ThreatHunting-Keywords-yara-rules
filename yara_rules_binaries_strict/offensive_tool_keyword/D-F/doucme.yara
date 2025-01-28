rule doucme
{
    meta:
        description = "Detection patterns for the tool 'doucme' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "doucme"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string1 = /\\"NSA0XF\$\\"/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string2 = /\/DoUCMe\.git/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string3 = /\\doucme\.csproj/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string4 = /\\doucme\.exe/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string5 = /\\doucme\.sln/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string6 = "A11E7DAE-21F2-46A8-991E-D38DEBE1650F" nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string7 = "All Done! Hack the planet!" nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string8 = "Ben0xA/DoUCMe" nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string9 = /DoUCMe\-main\\/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string10 = "Enumerating Administrators group, please wait" nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string11 = "Enumerating new user, please wait" nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string12 = "PASSWORD = \"Letmein123!" nocase ascii wide
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
