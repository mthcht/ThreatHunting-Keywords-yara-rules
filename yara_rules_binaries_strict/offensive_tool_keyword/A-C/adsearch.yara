rule adsearch
{
    meta:
        description = "Detection patterns for the tool 'adsearch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adsearch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string1 = /\s\-\-search\s\\"\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string2 = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=.{0,100}Admins/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string3 = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=MS\sSQL\sAdmins\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string4 = /\s\-\-search\s\\"\(\&\(objectCategory\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304\)\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string5 = /\/ADSearch\.git/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string6 = /adsearch.{0,100}\s\-\-domain\-admins/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string7 = /adsearch\.exe/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string8 = /ADSearch\.sln/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string9 = /ADSearch\\ADSearch\.cs/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string10 = /adsearch\-master\.zip/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string11 = "tomcarver16/ADSearch" nocase ascii wide
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
