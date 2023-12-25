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
        $string1 = /\s\-\-input\s10m_usernames\.txt/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string2 = /\s\-\-output\srootDSEs\.json\s\-\-dump/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string3 = /\/10m_usernames\.txt/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string4 = /\/ldapnomnom\@latest/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string5 = /\\10m_usernames\.txt/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string6 = /ldapnomnom\s/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string7 = /ldapnomnom\s\-\-input/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string8 = /ldapnomnom\-darwin\-/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string9 = /ldapnomnom\-linux\-/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string10 = /ldapnomnom\-main/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string11 = /ldapnomnom\-windows\-386\.exe/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string12 = /ldapnomnom\-windows\-amd64\.exe/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string13 = /ldapnomnom\-windows\-arm64\.exe/ nocase ascii wide

    condition:
        any of them
}
