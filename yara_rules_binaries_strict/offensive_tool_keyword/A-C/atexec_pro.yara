rule atexec_pro
{
    meta:
        description = "Detection patterns for the tool 'atexec-pro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string1 = /\satexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string2 = /\/atexec\-pro\.git/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string3 = /\/atexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string4 = /\/libs\/powershells\/upload\.ps1/
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string5 = /\/Rubeus\.exe/
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string6 = /\\atexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string7 = /\\atexec\-pro\-main/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string8 = "10dbc6cb2d71505d7add5a2927228077142851657f2578b9c774656505338d32" nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string9 = /ATShell\s\(\%s\@\%s\)\>\s/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string10 = "dc5a1f72ecaa1cddb1df73ddd075819eb5d2d35f95ea11639cfa1e189ed15217" nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string11 = /impacket\.dcerpc/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string12 = /impacket\.krb5/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string13 = "Ridter/atexec-pro" nocase ascii wide
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
