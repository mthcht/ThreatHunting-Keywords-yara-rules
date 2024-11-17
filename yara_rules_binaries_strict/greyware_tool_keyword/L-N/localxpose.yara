rule localxpose
{
    meta:
        description = "Detection patterns for the tool 'localxpose' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localxpose"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string1 = /\.loclx\.io\:/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string2 = /\/.{0,100}\.loclx\.io/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string3 = /\/loclx\.exe/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string4 = /\/loclx\-windows\-amd64\.zip/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string5 = /\\loclx\.exe/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string6 = /\\loclx\-windows\-amd64\.zip/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string7 = /17a9356024d2fa2ae8f327fc5babc10eb859e0c433e768cd03a50dd9c7880601/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string8 = /33ab2fa30777211450e30c21c45803cdf076cb991f05691bd60aef97a8183e04/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string9 = /api\.localxpose\.io/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string10 = /brew\sinstall\s\-\-cask\slocalxpose/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string11 = /cd1978742a4afdbaaa15bf712d5c90bef4144caa99024df98f6a9ad58043ae85/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string12 = /choco\sinstall\slocalxpose/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string13 = /https\:\/\/localxpose\.io\/download/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string14 = /localxpose\/localxpose/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string15 = /loclx\stunnel\sconfig\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string16 = /loclx\stunnel\shttp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string17 = /loclx\stunnel\stcp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string18 = /loclx\stunnel\stls\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string19 = /loclx\stunnel\sudp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string20 = /loclx\.exe\stunnel\shttp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string21 = /loclx\.exe\stunnel\stcp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string22 = /loclx\.exe\stunnel\stls\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string23 = /loclx\.exe\stunnel\sudp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string24 = /loclx\-client\.s3\.amazonaws\.com/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string25 = /npm\sinstall\slocalxpose/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string26 = /snap\sinstall\slocalxpose/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string27 = /yarn\sadd\slocalxpose/ nocase ascii wide
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
