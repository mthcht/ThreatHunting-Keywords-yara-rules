rule spellbound
{
    meta:
        description = "Detection patterns for the tool 'spellbound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spellbound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string1 = /\sspellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string2 = /\sspellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string3 = /\/spellbound\.git/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string4 = /\/spellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string5 = /\/spellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string6 = /\\spellbound\-main/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string7 = /\\spellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string8 = /\\spellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string9 = /5dec1cfe7c0c2ec55c17fb44b43f7d14/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string10 = /mhuzaifi0604\/spellbound/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string11 = /payload_msf\.c/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string12 = /payload_msf\.exe/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string13 = /payload_spellshell\.c/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string14 = /payload_spellshell\.exe/ nocase ascii wide
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
