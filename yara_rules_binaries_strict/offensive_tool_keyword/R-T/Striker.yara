rule Striker
{
    meta:
        description = "Detection patterns for the tool 'Striker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Striker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string1 = /\.\/redirector\.py\s/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string2 = /\.striker\.local/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string3 = /\/agent\/C\/src\// nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string4 = /\/redirector\/redirector\.py/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string5 = /\/sites\-available\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string6 = /\/sites\-enabled\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string7 = /\/striker\.c/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string8 = /\/Striker\.git/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string9 = /\/striker\.local/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string10 = /4g3nt47\/Striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string11 = /bin\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string12 = /c2\.striker\./ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string13 = /localhost\:3000.{0,100}striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string14 = /nginx\/striker\.log/ nocase ascii wide
        // Description: Recon & Vulnerability Scanning Suite for web services
        // Reference: https://github.com/s0md3v/Striker
        $string15 = /s0md3v.{0,100}Striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string16 = /src\/obfuscator\.c/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string17 = /VITE_STRIKER_API/ nocase ascii wide
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
