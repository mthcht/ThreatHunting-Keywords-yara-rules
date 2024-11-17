rule Invoke_DumpMDEConfig
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DumpMDEConfig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DumpMDEConfig"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string1 = /\[\+\]\sDefender\sConfig\sDumped\sto\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string2 = /\[\+\]\sDumped\sAllowed\sThreats\sto\s.{0,100}\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string3 = /\[\+\]\sDumped\sExclusion\sPaths\sto\sExclusionPaths\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string4 = /\[\+\]\sDumped\sExploit\sGuard\sProtection\sHistory/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string5 = /\[\+\]\sDumped\sFirewall\sExclusions\sto\s/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string6 = /\[\+\]\sDumped\sProtection\sHistory\sto\sProtectionHistory\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string7 = /\[\+\]\sDumping\sDefender\sExcluded\sPaths/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string8 = /\[\+\]\sDumping\sDefender\sProtection\sHistory/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string9 = /\[\+\]\sDumping\sEnabled\sASR\sRules/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string10 = /\[System\[Provider\[\@Name\=\'Microsoft\-Windows\-Windows\sDefender\'\]\sand\s\(EventID\=5007\)\]\]/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string11 = /\\ExploitGuardProtectionHistory\.csv/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string12 = /78a098cf3b91a354d6425bb5c08af4a0cc137a71bec4ad44707d864e263a4384/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string13 = /Invoke\-DumpMDEConfig/ nocase ascii wide
        // Description: PowerShell script to dump Microsoft Defender Config, protection history and Exploit Guard Protection History (no admin privileges required )
        // Reference: https://github.com/BlackSnufkin/Invoke-DumpMDEConfig
        $string14 = /Query\-ExploitGuardProtectionHistory\s/ nocase ascii wide
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
