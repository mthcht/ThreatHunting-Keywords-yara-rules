rule ffuf
{
    meta:
        description = "Detection patterns for the tool 'ffuf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ffuf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string1 = /\s\-o\sffuf\.csv/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string2 = /\/ffuf\.git/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string3 = /\/ffuf\/ffufrc/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string4 = /cd\sffuf/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string5 = /ffuf\s.{0,100}\-input\-cmd/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string6 = /ffuf\s.{0,100}\-u\shttp/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string7 = /ffuf\s\-c\s/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string8 = /ffuf\s\-w\s/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string9 = /ffuf\.exe/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string10 = /ffuf\/ffuf/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string11 = /ffuf_.{0,100}_freebsd_.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string12 = /ffuf_.{0,100}_linux_.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string13 = /ffuf_.{0,100}_macOS_.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string14 = /ffuf_.{0,100}_openbsd_.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string15 = /ffuf_.{0,100}_windows_.{0,100}\.zip/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string16 = /ffuf\-master\.zip/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string17 = /fuff\s.{0,100}\-input\-shell/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string18 = /fuff\s.{0,100}\-scraperfile/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string19 = /fuff\s.{0,100}\-scrapers/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string20 = /https\:\/\/ffuf\.io\.fi/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string21 = /https\:\/\/ffuf\.io\/FUZZ/ nocase ascii wide
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
