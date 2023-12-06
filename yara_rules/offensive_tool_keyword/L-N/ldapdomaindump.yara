rule ldapdomaindump
{
    meta:
        description = "Detection patterns for the tool 'ldapdomaindump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapdomaindump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string1 = /\sdomainDumper/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string2 = /\/john\.git/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string3 = /bin\/ldd2pretty/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string4 = /dirkjan\@sanoweb\.nl/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string5 = /domainDumpConfig/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string6 = /getAllUserSpns/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string7 = /ldapdomaindump/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string8 = /ldd2bloodhound/ nocase ascii wide

    condition:
        any of them
}
