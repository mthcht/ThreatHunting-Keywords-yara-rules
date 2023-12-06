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
        $string1 = /\s\-method\s.{0,1000}\s\-nthash\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string2 = /\.py\s\-method\sBOTH\s\-dc\-ip\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string3 = /\.py\s\-method\sLDAPS\s\-dc\-ip\s/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string4 = /\/LdapRelayScan\.git/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string5 = /LdapRelayScan\.py/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string6 = /LdapRelayScan\-main/ nocase ascii wide
        // Description: Check for LDAP protections regarding the relay of NTLM authentication
        // Reference: https://github.com/zyn3rgy/LdapRelayScan
        $string7 = /zyn3rgy\/LdapRelayScan/ nocase ascii wide

    condition:
        any of them
}
