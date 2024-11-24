rule LdapRelayScan
{
    meta:
        description = "Detection patterns for the tool 'LdapRelayScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdapRelayScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string1 = /\s\-method\s.{0,100}\s\-nthash\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string2 = /\.py\s\-method\sBOTH\s\-dc\-ip\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string3 = /\.py\s\-method\sLDAPS\s\-dc\-ip\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string4 = /\/LdapRelayScan\.git/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string5 = "037abc006fd6d9877d3f63baa4d32ebedd18b5a1ce6f51c22aa0d18c7ad1e352" nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string6 = /LdapRelayScan\.py/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string7 = "LdapRelayScan-main" nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string8 = "zyn3rgy/LdapRelayScan" nocase ascii wide
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
