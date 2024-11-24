rule NLBrute
{
    meta:
        description = "Detection patterns for the tool 'NLBrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NLBrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string1 = /\/NLBrute.{0,100}\.rar/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string2 = /\/NLBrute.{0,100}\.zip/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string3 = /\/NLBrute\.exe/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string4 = /\[Reflection\.Assembly\]\:\:Load\(.{0,100}\[Char\]\(.{0,100}\)\+\[Char\]\(.{0,100}\)\+.{0,100}\+\[Char\]\(.{0,100}\)/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string5 = /\\NLBrute.{0,100}\.rar/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string6 = /\\NLBrute.{0,100}\.zip/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string7 = /\\NLBrute\.exe/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string8 = "2f40452382f378c481ce9622ea6f10cfb0275cad138c6a45fe16144111fdfa77" nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string9 = "4781b10d0dae27a772518c9167b3a654c46017897bc73ce4540f4bfca33e9b58" nocase ascii wide
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
