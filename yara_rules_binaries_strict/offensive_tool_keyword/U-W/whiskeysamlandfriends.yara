rule whiskeysamlandfriends
{
    meta:
        description = "Detection patterns for the tool 'whiskeysamlandfriends' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whiskeysamlandfriends"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string1 = /\s\-\-adfs\-host\s.{0,100}\s\-\-krb\-key\s.{0,100}\s\-\-krb\-ticket\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string2 = /\s\-\-target\-user\s.{0,100}\s\-\-dc\-ip\s.{0,100}\s\-command\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string3 = /\sticketsplease\./ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string4 = /\/shocknawe\// nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string5 = /\/ticketer\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string6 = /\/ticketsplease\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string7 = /ADFSpoof\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string8 = /dcsync\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string9 = /generate_golden_saml/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string10 = /import\sDCSYNC/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string11 = /shocknawe\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string12 = /smb\.dcsync/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string13 = /ticketsplease\sadfs\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string14 = /ticketsplease\sazure\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string15 = /ticketsplease\sdcsync\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string16 = /ticketsplease\sldap\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string17 = /ticketsplease\ssaml\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string18 = /ticketsplease\sticket\s\-\-domain/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string19 = /ticketsplease\.modules\./ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string20 = /whiskeysaml\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string21 = /whiskeysamlandfriends/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
