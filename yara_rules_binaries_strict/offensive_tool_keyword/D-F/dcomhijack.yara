rule dcomhijack
{
    meta:
        description = "Detection patterns for the tool 'dcomhijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcomhijack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string1 = /\/dcomhijack\.cna/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string2 = /\/dcomhijack\.git/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string3 = /\/dcomhijack\.git/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string4 = /\/dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string5 = /\\dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string6 = "2fe3e062aad09c372500bdef858a32344d95c7b8036d4cb5f0091a2db17b446f" nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string7 = "9f1186262760c8424674045530bb64d541acbd5a5364e5e56f23cae01243a59e" nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string8 = /dcomhijack\.cna/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string9 = /dcomhijack\.py\s\-object\s/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string10 = /dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string11 = "dcomhijack-main" nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string12 = /upload\-dll\s.{0,100}\s.{0,100}\.dll/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string13 = "WKL-Sec/dcomhijack" nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string14 = "WKL-Sec/dcomhijack" nocase ascii wide
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
