rule ldapminer
{
    meta:
        description = "Detection patterns for the tool 'ldapminer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapminer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a tool I wrote to collect information from different LDAP Server implementation. This was written in C with the Netscape C
        // Reference: https://sourceforge.net/projects/ldapminer/
        $string1 = /LdapMiner/ nocase ascii wide

    condition:
        any of them
}
