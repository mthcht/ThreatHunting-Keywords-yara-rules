rule ACEshark
{
    meta:
        description = "Detection patterns for the tool 'ACEshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACEshark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string1 = /\sACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string2 = /\.ACEshark\.log/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string3 = /\/\.ACEshark/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string4 = /\/ACEshark\.git/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string5 = /\/ACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string6 = /\\ACEshark\.log/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string7 = /\\ACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string8 = "0e9af89e0f2faa8d7f92d6e9538e19f82c701c798031d890978845e388b85ba6" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string9 = "7fa5122ff9fabaf2676064087eacaf4a63b386bb27d50ac345ff4bdbe6a4f7d5" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string10 = "e07330a2c8c8678fce26c761437a3ed5cf38881baea403a376a5b3b9b5ef9d27" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string11 = "t3l3machus/ACEshark" nocase ascii wide
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
