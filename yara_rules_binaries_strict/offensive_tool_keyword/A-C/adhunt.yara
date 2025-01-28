rule adhunt
{
    meta:
        description = "Detection patterns for the tool 'adhunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adhunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string1 = /\sadhunt\.py\s/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string2 = /\/ADHunt\.git/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string3 = /\/adhunt\.py/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string4 = /\\adhunt\.py/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string5 = /ad_dns_dump\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string6 = /ADHunt\-main\.zip/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string7 = /dcenum\.run/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string8 = /delegation_constrained_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string9 = /delegation_constrained_w_protocol_transition_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string10 = /delegation_rbcd_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string11 = /delegation_unconstrained_objects\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string12 = "karendm/ADHunt" nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string13 = /objects_constrained_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string14 = /objects_rbcd_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string15 = /objects_unconstrained_delegation_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string16 = /smbenum\.run/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string17 = /users_asreproast\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string18 = /users_dcsrp_full\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string19 = /users_kerberoasting\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string20 = /users_no_req_pass\.txt/ nocase ascii wide
        // Description: Tool for exploiting Active Directory Enviroments - enumeration
        // Reference: https://github.com/karendm/ADHunt
        $string21 = /users_no_req_pass_full\.txt/ nocase ascii wide
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
