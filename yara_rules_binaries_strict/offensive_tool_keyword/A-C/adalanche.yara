rule adalanche
{
    meta:
        description = "Detection patterns for the tool 'adalanche' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adalanche"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string1 = /\s\-\-authmode\sntlm\s\-\-username\s.{0,100}\s\-\-password\s/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string2 = /\scollect\sactivedirectory\s\-\-/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string3 = /\/adalanche\/modules\// nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string4 = /activedirectory\/pwns\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string5 = /adalanche\sanalyze/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string6 = /adalanche\scollect/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string7 = /adalanche\-.{0,100}\.exe/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string8 = /Adalanche\.git/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string9 = /adalanche\-collector/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string10 = /adexplorer\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string11 = /HasAutoAdminLogonCredentials/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string12 = /HasSPNNoPreauth/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string13 = /ldap_enums\.go/ nocase ascii wide
        // Description: Active Directory ACL Visualizer and Explorer - who's really Domain Admin?
        // Reference: https://github.com/lkarlslund/Adalanche
        $string14 = /lkarlslund\/Adalanche/ nocase ascii wide
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
