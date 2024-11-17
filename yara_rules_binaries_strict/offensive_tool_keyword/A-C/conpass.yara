rule conpass
{
    meta:
        description = "Detection patterns for the tool 'conpass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conpass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string1 = /b09a40f998e8bc112841842ed56d8e843e5df98f4b53657098924fd10325a4b9/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string2 = /conpass\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string3 = /conpass\sv.{0,100}\s\-\sContinuous\spassword\sspraying\stool/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string4 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string5 = /ed99b1d4757d0848ced6b91f18326c42127f6f79ad1cc7e7fafeee91388004e3/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string6 = /from\sconpass\.ntlminfo\simport\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string7 = /from\sconpass\.password\simport\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string8 = /Hackndo\/conpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string9 = /impacket\.smbconnection/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string10 = /login\-securite\/conpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string11 = /pip\sinstall\sconpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string12 = /Romain\sBentz\s\(pixis\s\-\s\@hackanddo\)/ nocase ascii wide
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
