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
        $string3 = /ldapnomnom\s\-\-input/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string4 = /ldapnomnom/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string5 = /ldapnomnom\-darwin\-/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string6 = /ldapnomnom\-linux\-/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string7 = /ldapnomnom\-main/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string8 = /ldapnomnom\-windows\-386\.exe/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string9 = /ldapnomnom\-windows\-amd64\.exe/ nocase ascii wide
        // Description: Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
        // Reference: https://github.com/lkarlslund/ldapnomnom
        $string10 = /ldapnomnom\-windows\-arm64\.exe/ nocase ascii wide

    condition:
        any of them
}