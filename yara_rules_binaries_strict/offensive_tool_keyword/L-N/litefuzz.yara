rule litefuzz
{
    meta:
        description = "Detection patterns for the tool 'litefuzz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "litefuzz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string1 = /\.\/litefuzz\.py/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string2 = "/sec-tools/litefuzz" nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string3 = /AcroRd32\.exe\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string4 = "antiword FUZZ" nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string5 = "litefuzz -lk -c" nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string6 = "litefuzz -s -a " nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string7 = /litefuzz.{0,100}\s\-l\s\-c/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string8 = /litefuzz\.py\s/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string9 = /litefuzz\\fuzz\.py/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string10 = "--mutator N" nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string11 = /mutator\.py\s/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string12 = "notepad FUZZ" nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string13 = /puttygen\.exe\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string14 = /test_litefuzz\.py/ nocase ascii wide
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
