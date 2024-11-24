rule SirTunnel
{
    meta:
        description = "Detection patterns for the tool 'SirTunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirTunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string1 = /\s\$domain\ssirtunnel\s\$domain\s\$serverPort/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string2 = /\ssirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string3 = "/config/apps/http/servers/sirtunnel/routes" nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string4 = /\/SirTunnel\.git/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string5 = /\/sirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string6 = /\\sirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string7 = "anderspitman/SirTunnel" nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string8 = "d5687d84d518119cbdd84183bfe8cb29009d054794b3aed5bda7ad117a7e4d5e" nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string9 = "daps94/SirTunnel" nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string10 = /http\:\/\/127\.0\.0\.1\:2019\/id\// nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string11 = "matiboy/SirTunnel" nocase ascii wide
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
