rule ldapnomnom
{
    meta:
        description = "Detection patterns for the tool 'ldapnomnom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapnomnom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string1 = /.{0,1000}\s\-\-input\s10m_usernames\.txt.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string2 = /.{0,1000}\s\-\-output\srootDSEs\.json\s\-\-dump.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string3 = /.{0,1000}ldapnomnom\s\-\-input.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string4 = /.{0,1000}ldapnomnom.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string5 = /.{0,1000}ldapnomnom\-darwin\-.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string6 = /.{0,1000}ldapnomnom\-linux\-.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string7 = /.{0,1000}ldapnomnom\-main.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string8 = /.{0,1000}ldapnomnom\-windows\-386\.exe.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string9 = /.{0,1000}ldapnomnom\-windows\-amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string10 = /.{0,1000}ldapnomnom\-windows\-arm64\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
