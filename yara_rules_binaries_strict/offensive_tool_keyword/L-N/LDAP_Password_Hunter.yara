rule LDAP_Password_Hunter
{
    meta:
        description = "Detection patterns for the tool 'LDAP-Password-Hunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAP-Password-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string1 = " FROM LDAPHUNTERFINDINGS" nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string2 = " INTO LDAPHUNTERFINDINGS" nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string3 = /\sldapph\.db/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string4 = /\/LDAP\-Password\-Hunter\.git/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string5 = /\/ldapph\.db/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string6 = /\\ldapph\.db/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string7 = "c850818a6b19486dae2a4c370797cbb4fa61a4ebd35cba8e94a60b54c4499c8b" nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string8 = /CREATE\sTABLE\s\[LDAPHUNTERFINDINGS\]/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string9 = "Creating a TGT ticket for the user" nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string10 = "DELETE FROM LDAPHUNTERFINDINGS" nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string11 = /getTGT\.py\s\-dc\-ip/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string12 = "INSERT INTO LDAPHUNTERFINDINGS " nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string13 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string14 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string15 = "LDAP PASSWORD ENUM" nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string16 = "LDAP PASSWORD HUNTER" nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string17 = /mv\s.{0,100}\.ccache\s.{0,100}\.ccache/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string18 = "oldboy21/LDAP-Password-Hunter" nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string19 = /password\|pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string20 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf\sfile\sis\sclean/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string21 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string22 = "Please be sure impacket is installed in your system" nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string23 = "Please be sure impacket is installed in your system" nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string24 = /pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string25 = "Results are on disk, enumerating next DC!" nocase ascii wide
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
