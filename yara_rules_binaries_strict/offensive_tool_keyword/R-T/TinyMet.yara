rule TinyMet
{
    meta:
        description = "Detection patterns for the tool 'TinyMet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TinyMet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string1 = /\/tinymet\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string2 = /\\tinymet\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string3 = /0_evil\.com_4444\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string4 = "331952cdf2781133eafa25e3115db3e9cfb2cbf9b208fbcb6a462eab2e314343" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string5 = "3e8b305a4b6157e6f3ed492c596cfda37d27bf63e1532516aa96ec10eed3d166" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string6 = "DA06A931-7DCA-4149-853D-641B8FAA1AB9" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string7 = /TinyMet\sv0\.2\\ntinymet\.com/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string8 = /www\.tinymet\.com/ nocase ascii wide
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
