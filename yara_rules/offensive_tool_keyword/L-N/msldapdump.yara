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
        $string1 = /.{0,1000}\.adminusers\.txt.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string2 = /.{0,1000}\.asreproast\.txt.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string3 = /.{0,1000}\.kerberoast\.txt.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string4 = /.{0,1000}\.ldapdump\.txt.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string5 = /.{0,1000}\.unconstrained\.txt.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string6 = /.{0,1000}\/msLDAPDump.{0,1000}/ nocase ascii wide
        // Description: LDAP enumeration tool implemented in Python3
        // Reference: https://github.com/dievus/msLDAPDump
        $string7 = /.{0,1000}msLDAPDump\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
