rule FormThief
{
    meta:
        description = "Detection patterns for the tool 'FormThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FormThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string1 = /\/FormThief\.git/ nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string2 = /\\FormThief\-main/ nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string3 = "10CC4D5B-DC87-4AEB-887B-E47367BF656B" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string4 = "4B2E3A60-9A8F-4F36-8692-14ED9887E7BE" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string5 = "4ED3C17D-33E6-4B86-9FA0-DA774B7CD387" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string6 = "78DE9716-84E8-4469-A5AE-F3E43181C28B" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string7 = "D6948EFC-AA15-413D-8EF1-032C149D3FBB" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string8 = "mlcsec/FormThief" nocase ascii wide
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
