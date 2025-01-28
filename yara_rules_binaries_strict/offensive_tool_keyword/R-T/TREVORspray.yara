rule TREVORspray
{
    meta:
        description = "Detection patterns for the tool 'TREVORspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TREVORspray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string1 = /\/TREVORspray\.git/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string2 = /\/trevorspray\.log/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string3 = /\/tried_logins\.txt/
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string4 = "blacklanternsecurity/trevorproxy" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string5 = "blacklanternsecurity/TREVORspray" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string6 = "import BaseSprayModule" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string7 = /spray.{0,100}\s\-\-recon\s.{0,100}\..{0,100}\s\-u\s.{0,100}\.txt\s\-\-threads\s10/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string8 = "TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string9 = "trevorproxy ssh" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string10 = "trevorproxy subnet" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string11 = "trevorspray -" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string12 = /trevorspray\.cli/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string13 = /trevorspray\.enumerators/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string14 = /trevorspray\.looters/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string15 = /trevorspray\.py/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string16 = /trevorspray\.sprayers/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string17 = /trevorspray\/existent_users\.txt/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string18 = /trevorspray\/valid_logins\.txt/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string19 = "TREVORspray-dev" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string20 = "TREVORspray-master" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string21 = "TREVORspray-trevorspray" nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string22 = "Your Moms Smart Vibrator" nocase ascii wide
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
