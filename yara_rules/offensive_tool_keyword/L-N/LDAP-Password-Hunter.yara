rule LDAP_Password_Hunter
{
    meta:
        description = "Detection patterns for the tool 'LDAP-Password-Hunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAP-Password-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string1 = /CREATE\sTABLE\s\[LDAPHUNTERFINDINGS\]/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string2 = /Creating\sa\sTGT\sticket\sfor\sthe\suser/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string3 = /DELETE\sFROM\sLDAPHUNTERFINDINGS/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string4 = /getTGT\.py\s\-dc\-ip/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string5 = /INSERT\sINTO\sLDAPHUNTERFINDINGS\s/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string6 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string7 = /LDAP\sPASSWORD\sENUM/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string8 = /mv\s.{0,1000}\.ccache\s.{0,1000}\.ccache/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string9 = /password\|pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string10 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf\sfile\sis\sclean/ nocase ascii wide
        // Description: LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string11 = /Please\sbe\ssure\simpacket\sis\sinstalled\sin\syour\ssystem/ nocase ascii wide

    condition:
        any of them
}
