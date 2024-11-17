rule ADPassHunt
{
    meta:
        description = "Detection patterns for the tool 'ADPassHunt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADPassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string1 = /\sADPassHunt\.GetGPPPassword/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string2 = /\[ADA\]\sSearching\sfor\saccounts\swith\smsSFU30Password\sattribute/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string3 = /\[ADA\]\sSearching\sfor\saccounts\swith\suserpassword\sattribute/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string4 = /\[GPP\]\sSearching\sfor\spasswords\snow/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string5 = /\\ADPassHunt\.pdb/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string6 = /\\ADPassHunt\\/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string7 = /\>ADPassHunt\</ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string8 = /73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string9 = /AdPassHunt\s\(PUA\)/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string10 = /ADPassHunt\.exe/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string11 = /Get\-GPPAutologons/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string12 = /Get\-GPPPasswords/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string13 = /HackTool\:Win32\/PWDump/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string14 = /HackTool\:Win32\/PWDump/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string15 = /Win\.Tool\.ADPassHunt\-/ nocase ascii wide
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
