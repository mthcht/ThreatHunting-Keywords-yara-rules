rule Burntcigar_KillAV
{
    meta:
        description = "Detection patterns for the tool 'Burntcigar KillAV' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Burntcigar KillAV"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string1 = /\/KillAV\.exe/ nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string2 = /\\KillAV\.exe/ nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string3 = "7010b962fefc8fb879e19b1f170345478875b81748b5a146218a7b0337627060" nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string4 = "aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03" nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string5 = /WorkNew19\\KillAV\\Release\\KillAV\.pdb/ nocase ascii wide
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
