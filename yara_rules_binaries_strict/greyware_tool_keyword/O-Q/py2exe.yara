rule py2exe
{
    meta:
        description = "Detection patterns for the tool 'py2exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "py2exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string1 = " py2exe" nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string2 = "/py2exe/" nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string3 = /\\py2exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string4 = "py2exe " nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string5 = /py2exe.{0,100}\.exe\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string6 = /py2exe.{0,100}\.msi\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string7 = /py2exe.{0,100}\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string8 = /py2exe\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string9 = /py2exe\-.{0,100}\.whl/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string10 = /py2exe\.build_exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string11 = /py2exe\.freeze/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string12 = /py2exe\.git/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string13 = /py2exe_setuptools\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string14 = /py2exe\-master\.zip/ nocase ascii wide
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
