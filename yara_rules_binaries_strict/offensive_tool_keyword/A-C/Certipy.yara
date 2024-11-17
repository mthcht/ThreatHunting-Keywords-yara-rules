rule Certipy
{
    meta:
        description = "Detection patterns for the tool 'Certipy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certipy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string1 = /\scertipy\-ad/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string2 = /\s\-dns\-tcp\s\-nameserver\s.{0,100}\s\-dc\-ip/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string3 = /\s\-no\-pass\s\-dns\-tcp\s\-nameserver/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string4 = /\s\-old\-bloodhound/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string5 = /\sshadow\sauto\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-account\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string6 = /\/Certipy\.git/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string7 = /\/Certipy\// nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string8 = /certipy\saccount\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string9 = /certipy\sauth\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string10 = /certipy\sca\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string11 = /certipy\sca\s\-backup/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string12 = /certipy\scert\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string13 = /certipy\sfind\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string14 = /certipy\sforge\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string15 = /certipy\sforge\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string16 = /certipy\srelay\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string17 = /certipy\sreq\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string18 = /certipy\sshadow\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string19 = /certipy\stemplate\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string20 = /certipy\-master\.zip/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string21 = /ly4k\/Certipy/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string22 = /certipy\s/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
