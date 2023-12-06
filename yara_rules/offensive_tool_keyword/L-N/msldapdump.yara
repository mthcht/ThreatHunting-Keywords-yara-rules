rule msldapdump
{
    meta:
        description = "Detection patterns for the tool 'msldapdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msldapdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string1 = /\.adminusers\.txt/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string2 = /\.asreproast\.txt/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string3 = /\.kerberoast\.txt/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string4 = /\.ldapdump\.txt/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string5 = /\.unconstrained\.txt/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string6 = /\/msLDAPDump/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string7 = /msLDAPDump\.py/ nocase ascii wide

    condition:
        any of them
}
