rule SharpLdapRelayScan
{
    meta:
        description = "Detection patterns for the tool 'SharpLdapRelayScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLdapRelayScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharLdapRealyScan is a tool to check Domain Controllers for LDAP server protections regarding the relay of NTLM authenticationvand it's a C# port of?LdapRelayScan
        // Reference: https://github.com/klezVirus/SharpLdapRelayScan
        $string1 = /\.exe\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sLDAPS/ nocase ascii wide
        // Description: SharLdapRealyScan is a tool to check Domain Controllers for LDAP server protections regarding the relay of NTLM authenticationvand it's a C# port of?LdapRelayScan
        // Reference: https://github.com/klezVirus/SharpLdapRelayScan
        $string2 = /SharpLdapRelayScan/ nocase ascii wide

    condition:
        any of them
}
