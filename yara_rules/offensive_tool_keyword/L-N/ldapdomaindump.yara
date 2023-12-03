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
        $string1 = /.{0,1000}\sdomainDumper.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string2 = /.{0,1000}\/john\.git.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string3 = /.{0,1000}bin\/ldd2pretty.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string4 = /.{0,1000}dirkjan\@sanoweb\.nl.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string5 = /.{0,1000}domainDumpConfig.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string6 = /.{0,1000}getAllUserSpns.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string7 = /.{0,1000}ldapdomaindump.{0,1000}/ nocase ascii wide
        // Description: Active Directory information dumper via LDAP
        // Reference: https://github.com/dirkjanm/ldapdomaindump
        $string8 = /.{0,1000}ldd2bloodhound.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
