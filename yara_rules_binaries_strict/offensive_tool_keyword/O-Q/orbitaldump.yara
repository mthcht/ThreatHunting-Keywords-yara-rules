rule orbitaldump
{
    meta:
        description = "Detection patterns for the tool 'orbitaldump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "orbitaldump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string1 = /\/orbitaldump\.git/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string2 = "k4yt3x/orbitaldump" nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string3 = /orbitaldump\.py/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string4 = "orbitaldump/orbitaldump" nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string5 = "python -m orbitaldump " nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string6 = "python3 -m orbitaldump " nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string7 = "--user orbitaldump" nocase ascii wide
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
