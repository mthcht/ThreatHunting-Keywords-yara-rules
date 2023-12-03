rule LdapRelayScan
{
    meta:
        description = "Detection patterns for the tool 'LdapRelayScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdapRelayScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string1 = /.{0,1000}\s\-method\s.{0,1000}\s\-nthash\s.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string2 = /.{0,1000}\.py\s\-method\sBOTH\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string3 = /.{0,1000}\.py\s\-method\sLDAPS\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string4 = /.{0,1000}\/LdapRelayScan\.git.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string5 = /.{0,1000}LdapRelayScan\.py.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string6 = /.{0,1000}LdapRelayScan\-main.{0,1000}/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string7 = /.{0,1000}zyn3rgy\/LdapRelayScan.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
