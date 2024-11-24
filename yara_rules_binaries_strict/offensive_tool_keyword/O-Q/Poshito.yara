rule Poshito
{
    meta:
        description = "Detection patterns for the tool 'Poshito' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Poshito"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string1 = "/Poshito -w /Poshito/Poshito poshito" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string2 = /\/Poshito\.dll/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string3 = /\/Poshito\.exe/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string4 = /\/Poshito\.git/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string5 = "/Poshito/Poshito/Agent" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string6 = /\/PowerShdll\.exe/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string7 = /\[\+\]\sUPXed\ssuccessfully/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string8 = /\\patch_exit\.exe/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string9 = /\\Poshito\.dll/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string10 = /\\Poshito\.exe/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string11 = /\\PowerShdll\.exe/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string12 = ">PowerShdll<" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string13 = "a5d8564157388d8d628ba9b8785307fd8cbbf3b6fafc1cd46160712a0015ced6" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string14 = "d9fb91ea8b177ea86eefc1a62a875e55136fa268aa762fa44a377023f89b7673" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string15 = "da84dfd9b5b5f068189c1a37f2f3003c402ebf6bc1080e70caa82c51ee4c2bc8" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string16 = "docker build -t poshito" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string17 = /go\sinstall\smvdan\.cc\/garble\@latest/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string18 = "itaymigdal/Poshito" nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string19 = /Password\sconfirmed\.\s\\nPoshito\sis\swelcoming\syou/ nocase ascii wide
        // Description: Poshito is a Windows C2 over Telegram
        // Reference: https://github.com/itaymigdal/Poshito
        $string20 = "Poshito-C2 agent builder" nocase ascii wide
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
