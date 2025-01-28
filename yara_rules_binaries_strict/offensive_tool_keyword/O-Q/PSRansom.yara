rule PSRansom
{
    meta:
        description = "Detection patterns for the tool 'PSRansom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRansom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string1 = " PopUpRansom" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string2 = "/PSRansom -" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string3 = /\\PSRansom\s\-/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string4 = "644e2fa03a4d45b8d0417819a7548339069df8d405131039006968b312c8c6f4" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string5 = "C2Server by @JoelGMSec" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string6 = /C2Server\.ps1/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string7 = "cf78b329b4dcb1c211415309e2ddbf80833ad1669fd142a67c916aa6a8cecb88" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string8 = "JoelGMSec/PSRansom" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string9 = "PSRansom by @JoelGMSec" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string10 = /PSRansom\.ps1/ nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string11 = "pwd/C2Files/" nocase ascii wide
        // Description: PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server. you can exfiltrate files and receive client information via HTTP.
        // Reference: https://github.com/JoelGMSec/PSRansom
        $string12 = /pwd\\C2Files\\/ nocase ascii wide
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
