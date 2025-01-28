rule fuegoshell
{
    meta:
        description = "Detection patterns for the tool 'fuegoshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuegoshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string1 = /\sgenerate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string2 = /\sgenerate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string3 = /\$myC2ipAdress/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string4 = /\$myVictimIPAdress/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string5 = /\/fuegoshell\.git/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string6 = /\/generate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string7 = /\/generate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string8 = /\[\+\]\sNew\sincoming\sshell\sfrom\s\:\s/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string9 = /\\generate_bind_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string10 = /\\generate_reverse_fuegoshell\.ps1/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string11 = /\>\\fuego\-control/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string12 = /\>\\fuego\-data/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string13 = /\>\\fuegoshell/ nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string14 = "5b64c12376f1ec1b876ede9b84f6883ee5f1ee5065e945dc2115c5e04c02aadf" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string15 = "6c6c37d26619bfe90a84e3e70c8dd45073488e120d239500bef10977f8523073" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string16 = "fuegoShell-bind>" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string17 = "Fuegoshell-client started" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string18 = "fuegoShell-reverse>" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string19 = "Fuegoshell-server started" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string20 = "Here are the oneliners for reverse shell using rpc named pipes" nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string21 = /v1k1ngfr\.github\.io\/fuegoshell\// nocase ascii wide
        // Description: Fuegoshell is a powershell oneliner generator for Windows remote shell re-using TCP 445
        // Reference: https://github.com/v1k1ngfr/fuegoshell
        $string22 = "v1k1ngfr/fuegoshell" nocase ascii wide
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
