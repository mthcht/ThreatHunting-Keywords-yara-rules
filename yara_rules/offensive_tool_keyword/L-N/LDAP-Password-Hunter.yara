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
        $string1 = /\sFROM\sLDAPHUNTERFINDINGS/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string2 = /\sINTO\sLDAPHUNTERFINDINGS/ nocase ascii wide
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
        $string7 = /c850818a6b19486dae2a4c370797cbb4fa61a4ebd35cba8e94a60b54c4499c8b/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string8 = /CREATE\sTABLE\s\[LDAPHUNTERFINDINGS\]/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string9 = /Creating\sa\sTGT\sticket\sfor\sthe\suser/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string10 = /DELETE\sFROM\sLDAPHUNTERFINDINGS/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string11 = /getTGT\.py\s\-dc\-ip/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string12 = /INSERT\sINTO\sLDAPHUNTERFINDINGS\s/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string13 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string14 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string15 = /LDAP\sPASSWORD\sENUM/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string16 = /LDAP\sPASSWORD\sHUNTER/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string17 = /mv\s.{0,1000}\.ccache\s.{0,1000}\.ccache/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string18 = /oldboy21\/LDAP\-Password\-Hunter/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string19 = /password\|pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string20 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf\sfile\sis\sclean/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string21 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string22 = /Please\sbe\ssure\simpacket\sis\sinstalled\sin\syour\ssystem/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string23 = /Please\sbe\ssure\simpacket\sis\sinstalled\sin\syour\ssystem/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string24 = /pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
        // Description: Password Hunter in Active Directory
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string25 = /Results\sare\son\sdisk\,\senumerating\snext\sDC\!/ nocase ascii wide

    condition:
        any of them
}
