rule dsquery
{
    meta:
        description = "Detection patterns for the tool 'dsquery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsquery"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with dsquery
        // Reference: N/A
        $string1 = /dsquery\s.{0,100}\s\-filter\s.{0,100}\(objectClass\=trustedDomain\).{0,100}\s\-attr\s/ nocase ascii wide
        // Description: Finding users Not Required to Have a Password
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string2 = /\-filter\s.{0,100}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32/ nocase ascii wide
        // Description: Finding accounts with Kerberos Pre-Authentication Disabled
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string3 = /\-filter\s.{0,100}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304/ nocase ascii wide
        // Description: Finding accounts with constrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string4 = /\-filter\s.{0,100}\(\&\(objectClass\=User\)\(msDS\-AllowedToDelegateTo\=/ nocase ascii wide
        // Description: Finding Kerberoastable Users
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string5 = /\-filter\s.{0,100}\(\&\(objectClass\=user\)\(servicePrincipalName\=.{0,100}\)\(\!\(cn\=krbtgt\)\)\(\!\(samaccounttype\=805306369/ nocase ascii wide
        // Description: Finding accounts with SPNs
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string6 = /\-filter\s.{0,100}\(\&\(objectClass\=User\)\(serviceprincipalname\=.{0,100}\)\(samaccountname\=.{0,100}\s\-limit\s0\s\-attr\ssamaccountname\sserviceprincipalname/ nocase ascii wide
        // Description: Finding accounts with unconstrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string7 = /\-filter\s.{0,100}\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)/ nocase ascii wide
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
