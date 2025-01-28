rule SCOMDecrypt
{
    meta:
        description = "Detection patterns for the tool 'SCOMDecrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCOMDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string1 = /\/SCOMDecrypt\.git/ nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string2 = "1637c5d66df6ce383aee2ab51e305ae9b654cfb4ceb21cf09d5123a54d7d7b7d" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string3 = "1b578e26adc91f95143cb5c8dcfa9c0baf76923ea2295cc45e2e7a99bd4a763c" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string4 = "5cdec4449506fe06e507619c8f1a66d890d96bb2ea30f6ea37f997853a52b243" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string5 = "C13C80ED-ED7A-4F27-93B1-DE6FD30A7B43" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string6 = "Invoke-SCOMDecrypt" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string7 = "nccgroup/SCOMDecrypt" nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string8 = /SCOMDecrypt\.csproj/ nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string9 = /SCOMDecrypt\.exe/ nocase ascii wide
        // Description: SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // Reference: https://github.com/nccgroup/SCOMDecrypt
        $string10 = /SCOMDecrypt\.ps1/ nocase ascii wide
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
