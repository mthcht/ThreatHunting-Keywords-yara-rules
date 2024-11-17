rule Supernova
{
    meta:
        description = "Detection patterns for the tool 'Supernova' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supernova"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string1 = /\.bin\s\-enc\src4\s\-lang\sc\s\-k\s3\s\-o\s.{0,100}\.bin/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string2 = /\.bin\s\-enc\src4\s\-lang\scsharp\s\-k\s9/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string3 = /\.bin\s\-enc\srot\s\-lang\scsharp\s\-k\s2\s\-d/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string4 = /\.bin\s\-enc\srot\s\-lang\srust\s\-k\s7/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string5 = /\.bin\s\-enc\sxor\s\-lang\scsharp\s\-k\s2\s\-v\snickvourd/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string6 = /\.bin\s\-enc\sxor\s\-lang\snim\s\-k\s4/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string7 = /\.exe\s.{0,100}\.bin\s\-enc\saes\s\-lang\scsharp/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string8 = /\/Supernova\.exe/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string9 = /\/Supernova\.git/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string10 = /\[\+\]\sGenerated\sXOR\skey\:\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string11 = /\[\+\]\sSave\sencrypted\sshellcode\sto\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string12 = /\[\+\]\sThe\sencrypted\spayload\swith\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string13 = /\\Supernova\.exe/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string14 = /build\sSupernova\.go/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string15 = /nickvourd\/Supernova/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string16 = /Supernova\.exe\s\-/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string17 = /Supernova\-main\.zip/ nocase ascii wide
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
